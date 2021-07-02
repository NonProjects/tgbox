from hashlib import sha256
from random import randrange
from asyncio import sleep

from subprocess import (
    Popen, PIPE, STDOUT
)
from typing import (
    BinaryIO, List, Iterable, 
    Generator, Union, Optional
)
from base64 import (
    urlsafe_b64encode as b64encode, # We use urlsafe base64.
    urlsafe_b64decode as b64decode
)
from struct import (
    pack as struct_pack, 
    unpack as struct_unpack
)
from os import remove as remove_file
from os.path import join as path_join

from .keys import Key
# todo: fix previews, so it always square.
class SearchFilter:
    def __init__(
            self, *, id: Optional[Union[int, List[int]]] = None, 
            time: Optional[Union[int, List[int]]] = None,
            comment: Optional[Union[str, List[str]]] = None,
            folder: Optional[Union[str, List[str]]] = None,
            file_name: Optional[Union[str, List[str]]] = None,
            min_size: Optional[Union[int, List[int]]] = None,
            max_size: Optional[Union[int, List[int]]] = None,
            file_salt: Optional[Union[bytes, List[bytes]]] = None,
            verbyte: Optional[Union[bytes, List[bytes]]] = None,
            exported: Optional[bool] = None
        ):
        '''
        Container that filters search in `RemoteBox` or 
        `DecryptedLocalBox`. All kwargs will be converted to `List`.
        
        If nothing specified, then search will nothing return. 
        
        You can extend all params via (i.e) `sf.id.append` or via
        concatenation (`+`) of two `SearchFilter` classes.
        
        You can make a new `SearchFilter` from two other 
        SearchFilters via floordiv (`//`).
        
        Any kwarg with `str` | `bytes` type 
        can also be regular expression.
        '''
        self.id = id if isinstance(id, list) else ([] if not id else [id])
        self.time = time if isinstance(time, list) else ([] if not time else [time])
        self.comment = comment if isinstance(comment, list) else ([] if not comment else [comment])
        self.folder = folder if isinstance(folder, list) else ([] if not folder else [folder])
        self.file_name = file_name if isinstance(file_name, list) else ([] if not file_name else [file_name])
        self.min_size = min_size if isinstance(min_size, list) else ([] if not min_size else [min_size])
        self.max_size = max_size if isinstance(max_size, list) else ([] if not max_size else [max_size])
        self.file_salt = file_salt if isinstance(file_salt, list) else ([] if not file_salt else [file_salt])
        self.verbyte = verbyte if isinstance(verbyte, list) else ([] if not verbyte else [verbyte])
        
        self.exported = exported
        
    def __hash__(self) -> int:
        return hash((
            self.id, self.time, self.comment, self.folder, self.exported,
            self.file_name, self.size, self._file_salt, self.verbyte
        ))
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __add__(self, other: 'SearchFilter') -> None:
        '''Extends filters with `other` filters.'''
        self.id.extend(other.id)
        self.time.extend(other.time)
        self.comment.extend(other.comment)
        self.folder.extend(other.folder)
        self.file_name.extend(other.file_name)
        self.min_size.extend(other.min_size)
        self.max_size.extend(other.max_size)
        self.file_salt.extend(other.file_salt)
        self.verbyte.extend(other.verbyte)
    
    def __floordiv__(self, other: 'SearchFilter') -> 'SearchFilter':
        '''
        Makes a new `SearchFilter` from `self` and `other` filters.
        Kwarg `exported` will be used from `other` class.
        '''
        return SearchFilter(
            id = self.id + other.id,
            time = self.time + other.time,
            comment = self.comment + other.comment,
            folder = self.folder + other.folder,
            file_name = self.file_name + other.file_name,
            min_size = self.min_size + other.min_size,
            max_size = self.max_size + other.max_size,
            file_salt = self.file_salt + other.file_salt,
            verbyte = self.verbyte + other.verbyte,
            exported = other.exported
        )
class OpenPretender:
    def __init__(self, aes_generator: Generator):
        '''
        Class to wrap Tgbox AES Generators and make it look
        like opened to "rb"-read file. Designed to work with Telethon.
        
        aes_generator (`Generator`):
            `crypto.aes_encrypt` or `crypto.aes_decrypt` generator.
        '''
        self._aes_generator = aes_generator
        self._buffered_bytes = b''
        self._stop_iteration = False
    
    def concat_preview(self, enc_preview: bytes) -> None:
        '''
        Concates preview to the file as (preview + file).
        Please note that `enc_preview` must be encrypted
        with `crypto.encrypt_preview` & == 5008 bytelength.
        '''
        assert len(enc_preview) == 5008 # Length must equals to 5008.
        
        if self._stop_iteration or self._buffered_bytes:
            raise Exception('Preview must before any usage of object.')
        else:
            self._buffered_bytes += enc_preview
    
    def read(self, size: int=-1) -> bytes:
        '''
        Returns `size` bytes from Generator.
        
        size (`int`):
            Amount of bytes to return. By default is negative
            (return all). 
        '''
        if not self._stop_iteration:
            if size < 0:
                b = b''.join(self._aes_generator)
                self._stop_iteration = True; return b
            else:
                while size > len(self._buffered_bytes):
                    try:
                        self._buffered_bytes += next(self._aes_generator)
                    except StopIteration:
                        self._stop_iteration = True
                        self._aes_generator = None; break

                block = self._buffered_bytes[:size]
                self._buffered_bytes = self._buffered_bytes[size:]
                
                return block
        else:    
            return b''
    
    def seekable(*args, **kwargs) -> bool:
        return False
    
    def close(self) -> None:
        self._stop_iteration = True

def make_folder_iv(key: Key) -> bytes:
    '''
    Returns IV that used for foldernames encryption.
    
    We use `sha256` of `Key` as IV ONLY for foldernames, 
    for other encryption `urandom(16)`. It's not affecting 
    security at all but simplify any kind of work with encrypted folders.
    '''
    return sha256(key.key).digest()[:16]
        
def int_to_bytes(int_: int) -> bytes:
    '''Converts int to bytes with Big byteorder.'''
    return int.to_bytes(int_, (int_.bit_length() + 7) // 8, 'big')

def bytes_to_int(bytes_: bytes) -> int:
    '''Converts bytes to int with Big byteorder.'''
    return int.from_bytes(bytes_, 'big')

def float_to_bytes(float_: float) -> bytes:
    '''Converts float to bytes.'''
    return struct_pack('!f', float_)

def bytes_to_float(bytes_: bytes) -> float:
    '''Converts bytes to float.'''
    return struct_unpack('!f', bytes_)[0]

def dump_to_datastring(bytes_list: Iterable[bytes]) -> str:
    '''
    base64encodes every bytes in list and returns joined
    with '|' string. I.e: 'SSdtIE5vbg==|U3RheWluJyBBbGl2ZSE='.
    '''
    datastring = ''    
    for i in bytes_list:
        datastring += b64encode(i).decode() + '|'
    return datastring[:-1]

def restore_datastring(datastring: str) -> List[bytes]:
    '''
    Splits by '|' datastring and base64decodes every element.
    Returns List[bytes].
    '''
    datastring = datastring.split('|')
    for indx, i in enumerate(datastring):
        datastring[indx] = b64decode(i)
    return datastring

async def get_media_duration(file_path: str) -> float:
    '''Returns video/audio duration with ffprobe.'''
    p = Popen(
        '''ffprobe -v error -show_entries format=duration -of '''
        f'''default=noprint_wrappers=1:nokey=1 {file_path}'''.split(' '),
        stdout=PIPE, stderr=STDOUT
    )
    while p.poll() == None:
        await sleep(0.1)
    return float(p.stdout.read())

async def make_media_preview(file_path: str, output_path: str='', x: int=110, y: int=110) -> bytes:
    '''Makes x:y sized thumbnail of the video/audio with ffmpeg.'''
    thumbnail_path = path_join(output_path, hex(randrange(2**128))[2:]) + '.jpg'
    p = Popen(
        f'''ffmpeg -i {file_path} -filter:v scale=-{x}:{y} -an '''
        f'''-loglevel quiet {thumbnail_path}'''.split(' ')
    )
    while p.poll() == None:
        await sleep(0.1)
    try:
        th = open(thumbnail_path,'rb').read()
        remove_file(thumbnail_path); return th
    except FileNotFoundError as e: # if something goes wrong then file not created
        raise TypeError('Not a video.') from e
            
async def make_image_preview(file_path: str, output_path: str='', x: int=110, y: int=110) -> bytes:
    '''Makes resized to x:y copy of the image with ffmpeg.'''
    thumbnail_path = path_join(output_path, hex(randrange(2**128))[2:]) + '.jpg'
    p = Popen(
        f'''ffmpeg -i {file_path} -vf scale={x}:{y} '''
        f'''-loglevel quiet {thumbnail_path}'''.split(' ')
    ) # todo
    while p.poll() == None:
        await sleep(0.1)
    try:
        th = open(thumbnail_path,'rb').read()
        remove_file(thumbnail_path); return th
    except FileNotFoundError as e: # if something goes wrong then file not created
        raise TypeError('Not a photo.') from e

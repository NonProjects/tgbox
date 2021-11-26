from hashlib import sha256
from random import randrange

# TODO: Investigate expediency
from asyncio import sleep

from subprocess import (
    Popen, PIPE, STDOUT
)
from typing import (
    BinaryIO, List, Union, Optional
)
from struct import (
    pack as struct_pack, 
    unpack as struct_unpack
)
from os import remove as remove_file
from pathlib import Path
from dataclasses import dataclass

from .constants import (
    VERBYTE_MAX, FILE_SALT_SIZE, FILE_NAME_MAX,
    FOLDERNAME_MAX, COMMENT_MAX, PREVIEW_MAX,
    DURATION_MAX, FILESIZE_MAX, PREFIX, 
    METADATA_MAX, FILEDATA_MAX, NAVBYTES_SIZE
)
from .keys import FileKey, MainKey
from .crypto import AESwState, aes_encrypt
from .errors import (
    ConcatError, PreviewImpossible, DurationImpossible
)

__all__ = [
    'prbg', 'anext', 
    'RemoteBoxFileMetadata', 
    'SearchFilter', 
    'OpenPretender', 
    'make_folder_id', 
    'int_to_bytes', 
    'bytes_to_int', 
    'float_to_bytes', 
    'bytes_to_float', 
    'get_media_duration', 
    'make_media_preview', 
    'make_image_preview'
]
# Will generate `size` pseudo-random bytes.
prbg = lambda size: bytes([randrange(256) for _ in range(size)])

try:
    anext() # Python 3.10+
except NameError:
    anext = lambda agen: agen.__anext__()

@dataclass
class RemoteBoxFileMetadata: # TODO __repr__?
    file_name: str
    enc_foldername: bytes
    filekey: FileKey
    comment: bytes
    size: int
    preview: bytes
    duration: float
    file_salt: bytes
    box_salt: bytes
    file_iv: bytes
    verbyte: bytes
    
    def __len__(self) -> int:
        if not hasattr(self, '_constructed'):
            return 0
        else:
            return len(self._constructed)
    
    def __iadd__(self, other: bytes) -> bytes:
        if not hasattr(self, '_constructed'):
            return other
        else:
            return self._constructed + other

    @property
    def constructed(self) -> Union[bytes, None]:
        if not hasattr(self, '_constructed'):
            return self.construct()
        else:
            return self._constructed

    def construct(self) -> bytes: 
        assert len(self.verbyte) == VERBYTE_MAX
        assert len(self.file_salt) == FILE_SALT_SIZE
        assert len(self.box_salt) == FILE_SALT_SIZE
        assert len(self.file_iv) == 16 
        assert len(self.file_name) <= FILE_NAME_MAX
        assert len(self.enc_foldername) <= FOLDERNAME_MAX
        assert len(self.comment) <= COMMENT_MAX
        assert len(self.preview) <= PREVIEW_MAX
        assert self.size <= FILESIZE_MAX
        assert self.duration <= DURATION_MAX
        
        metadata = (
            PREFIX + self.verbyte \
          + self.box_salt \
          + self.file_salt
        )
        filedata = (
            int_to_bytes(self.size,4) \
          + float_to_bytes(self.duration) \
          + int_to_bytes(len(self.enc_foldername),2,signed=False) \
          + self.enc_foldername + bytes([len(self.comment)]) \
          + self.comment + int_to_bytes(len(self.file_name),2,signed=False) \
          + self.file_name.encode()
        )
        filedata = next(aes_encrypt(
            filedata, self.filekey, yield_all=True
        ))
        assert len(filedata) <= FILEDATA_MAX

        if self.preview:
            preview = next(aes_encrypt(
                self.preview, self.filekey, yield_all=True
            ))
            assert len(preview) <= PREVIEW_MAX+16 
        else:
            preview = b''

        navbytes = int_to_bytes(len(filedata),3,signed=False) \
            + int_to_bytes(len(preview),3,signed=False)
        navbytes = next(aes_encrypt(
            navbytes, self.filekey, yield_all=True
        ))
        assert len(navbytes) == NAVBYTES_SIZE

        metadata += navbytes + filedata + preview
        assert len(metadata) <= METADATA_MAX
        
        self._constructed = metadata + self.file_iv
        return self._constructed
        
class SearchFilter:
    def __init__(
            self, *, id: Optional[Union[int, List[int]]] = None, 
            time: Optional[Union[int, List[int]]] = None,
            comment: Optional[Union[bytes, List[bytes]]] = None,
            folder: Optional[Union[bytes, List[bytes]]] = None,
            file_name: Optional[Union[bytes, List[bytes]]] = None,
            min_size: Optional[Union[int, List[int]]] = None,
            max_size: Optional[Union[int, List[int]]] = None,
            file_salt: Optional[Union[bytes, List[bytes]]] = None,
            verbyte: Optional[Union[bytes, List[bytes]]] = None,
            exported: Optional[bool] = None, re: Optional[bool] = None
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
        
        kwarg `re` will tell the `tgbox.api._search_func` that
        *all* filters that you use is Regular Expressions. 
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
        self.re = re
        
    def __hash__(self) -> int:
        return hash((
            self.id, self.time, self.comment, self.folder, self.exported, self.max_size,
            self.file_name, self.min_size, self.file_salt, self.verbyte, self.re
        ))
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __bool__(self) -> bool:
        '''Will return `True` if any(kwargs)'''
        return any((
            self.id, self.time, self.comment, self.folder, self.exported, self.max_size,
            self.file_name, self.min_size, self.file_salt, self.verbyte, self.re
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
            exported = other.exported, re = self.re
        )
class OpenPretender: 
    def __init__(self, flo: BinaryIO, aes_state: AESwState, mode: int):
        '''
        Class to wrap Tgbox AES Generators and make it look
        like opened to "rb"-read file. Designed to work with Telethon.
        
        flo (`BinaryIO`):
            File-like object. Like `open('file','rb')`.

        aes_state (`AESwState`):
            `AESwState` with Key and IV.

        mode (`int`):
            Mode of `AESwState` (1=Enc, 2=Dec).
        '''
        self._aes_state = aes_state
        self._mode, self._flo = mode, flo
        self._buffered_bytes = b''
        self._total_size = None

    def concat_metadata(self, metadata: bytes) -> None:
        '''Concates metadata to the file as (metadata + file).'''
        assert len(metadata) <= METADATA_MAX

        if self._total_size is not None or self._buffered_bytes:
            raise ConcatError('Concat must be before any usage of object.')
        else:
            self._buffered_bytes += metadata.constructed 
    
    def read(self, size: int=-1) -> bytes: 
        '''
        Returns `size` bytes from Generator.
        
        size (`int`):
            Amount of bytes to return. By default 
            is negative (return all). 
        '''
        if size % 16 and not size == -1:
            raise ValueError('size must be divisible by 16 or -1 (return all)')

        if self._total_size is None:
            self._total_size = self._flo.seek(0,2) # Move to file end
            self._flo.seek(0,0) # Move to file start
            
        if self._total_size <= 0 or size <= len(self._buffered_bytes) and size != -1:
            block = self._buffered_bytes[:size]
            self._buffered_bytes = self._buffered_bytes[size:]
        else:
            buffered = self._buffered_bytes
            self._buffered_bytes = b''

            if size == -1:
                self._total_size = 0
                if self._mode == 1:
                    return buffered + self._aes_state.encrypt(
                        self._flo.read(), pad=True)
                else:
                    return buffered + self._aes_state.decrypt(
                        self._flo.read(), unpad=True)
            
            elif self._mode == 1:
                chunk = self._flo.read(size)

                if len(chunk) % 16:
                    shift = int(-(len(chunk) % 16))
                else:
                    shift = None
                
                if self._total_size <= 0 or size > self._total_size or shift != None:
                    chunk = buffered + self._aes_state.encrypt(chunk, pad=True)
                else:
                    chunk = buffered + self._aes_state.encrypt(chunk, pad=False)
                
                shift = size if len(chunk) > size else None
                
                if shift is not None:
                    self._buffered_bytes = chunk[shift:]

                self._total_size -= size
                return chunk[:shift]
            else:
                self._total_size -= size
                if self._total_size <= 16:
                    block = aes_t(self._flo.read(size), unpad=True)
                else:
                    block = aes_t(self._flo.read(size), unpad=False)

        return block
    
    def seekable(*args, **kwargs) -> bool:
        return False
    
    def close(self) -> None:
        self._stop_iteration = True

def make_folder_id(mainkey: MainKey, foldername: bytes) -> bytes:
    return sha256(sha256(mainkey.key).digest() + foldername).digest()[:16]
        
def int_to_bytes(int_: int, length: Optional[int] = None, signed: Optional[bool] = True) -> bytes:
    '''Converts int to bytes with Big byteorder.'''
    length = length if length else (int_.bit_length() + 8) // 8
    return int.to_bytes(int_, length, 'big', signed=signed)

def bytes_to_int(bytes_: bytes, signed: Optional[bool] = True) -> int:
    '''Converts bytes to int with Big byteorder.'''
    return int.from_bytes(bytes_, 'big', signed=signed)

def float_to_bytes(float_: float) -> bytes:
    '''Converts float to bytes.'''
    return struct_pack('!f', float_)

def bytes_to_float(bytes_: bytes) -> float:
    '''Converts bytes to float.'''
    return struct_unpack('!f', bytes_)[0]

async def get_media_duration(file_path: str) -> float:
    '''Returns video/audio duration with ffprobe.'''
    p = Popen(
        ['ffprobe', '-v', 'error', '-show_entries', 'format=duration', 
         '-of', 'default=noprint_wrappers=1:nokey=1', file_path],
        stdout=PIPE, stderr=STDOUT
    )
    while p.poll() == None:
        await sleep(0.1)
    try:
        return float(p.stdout.read())
    except ValueError:
        raise DurationImpossible('Can\'t get media duration') from None 

async def make_media_preview(file_path: str, output_path: str='', x: int=128, y: int=-1) -> bytes:
    '''Makes x:y sized thumbnail of the video/audio with ffmpeg.'''
    thumbnail_path = Path(output_path, prbg(8).hex()+'.jpg')
    
    p = Popen(
        ['ffmpeg', '-i', file_path, '-filter:v', f'scale={x}:{y}', '-an',
        '-loglevel', 'quiet', '-q:v', '2', thumbnail_path]
    )
    while p.poll() == None:
        await sleep(0.1)
    try:
        th = open(thumbnail_path,'rb').read()
        remove_file(thumbnail_path); return th
    except FileNotFoundError as e: # if something goes wrong then file not created
        raise PreviewImpossible(f'Not a video. {e}') from None
            
async def make_image_preview(file_path: str, output_path: str='', x: int=128, y: int=-1) -> bytes:
    '''Makes resized to x:y copy of the image with ffmpeg.'''
    thumbnail_path = Path(output_path, prbg(8).hex()+'.jpg')
    
    p = Popen(
        ['ffmpeg', '-i', file_path, '-vf', f'scale={x}:{y}', 
         '-loglevel', 'quiet', '-q:v', '2', thumbnail_path]
    )
    while p.poll() == None:
        await sleep(0.1)
    try:
        th = open(thumbnail_path,'rb').read()
        remove_file(thumbnail_path); return th
    except FileNotFoundError as e: # if something goes wrong then file not created
        raise PreviewImpossible(f'Not a photo. {e}') from None

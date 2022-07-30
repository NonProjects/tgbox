"""This module stores utils required by API."""

try:
    from regex import search as re_search
except ImportError:
    from re import search as re_search

from asyncio import (
    iscoroutine, get_event_loop
)
from copy import deepcopy
from pprint import pformat
from hashlib import sha256
from random import randrange

from subprocess import (
    PIPE, STDOUT, 
    run as subprocess_run
)
from typing import (
    BinaryIO, List, Union, 
    Optional, Dict
)
from struct import (
    pack as struct_pack, 
    unpack as struct_unpack
)
from io import BytesIO
from os import PathLike
from pathlib import Path
from functools import partial
from dataclasses import dataclass
from os import remove as remove_file

from .constants import (
    VERBYTE_MAX, FILE_SALT_SIZE, FILE_NAME_MAX,
    FOLDERNAME_MAX, COMMENT_MAX, PREVIEW_MAX,
    DURATION_MAX, FILESIZE_MAX, PREFIX, FFMPEG,
    METADATA_MAX, FILEDATA_MAX, NAVBYTES_SIZE
)
from .errors import (
    ConcatError, 
    PreviewImpossible, 
    DurationImpossible
)
from .keys import FileKey, MainKey
from .crypto import AESwState as AES


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
try:
    anext() # Python 3.10+
except NameError:
    anext = lambda agen: agen.__anext__()

class _TypeList:
    """
    This is cutted version of ``list()`` that
    checks type on ``.append(...)``.

    You can specify multiply types with
    ``tuple``, e.g: ``_TypeList((int, float))``
    
    * The list will try to change value type if \
      ``isinstance(value, type_) is False`` to \
      ``value = type_(value)``. Otherwise ``TypeError``.
    """
    def __init__(self, type_, *args):
        self.type = type_ if isinstance(type_, tuple) else (type_,)
        self.list = [self.__check_type(i) for i in args]
    
    def __bool__(self):
        return bool(self.list)

    def __iter__(self):
        for i in self.list:
            yield i
    
    def __getitem__(self, sl):
        return self.list[sl]

    def __repr__(self) -> str:
        return f'_TypeList({self.type}, *{self.list})'

    def __check_type(self, value):
        for type_ in self.type:
            if isinstance(value, type_):
                return value
            else:
                try:
                    if isinstance(b'', type_):
                        # bytes(str) doesn't work
                        return type_(value,'utf-8')
                    else:
                        return type_(value)
                except:
                    pass
        else:
            raise TypeError(
                f'Invalid type! Expected {self.type}, got {type(value)}'
            )
    def append(self, value):
        self.list.append(self.__check_type(value))

    def extend(self, list):
        self.list.extend([self.__check_type(i) for i in list])

    def clear(self):
        self.list.clear()

class SearchFilter:
    """
    Container that filters search in ``DecryptedRemoteBox`` or     
    ``DecryptedLocalBox``.

    The ``SearchFilter`` has **two** filters: the **Include**
    and **Exclude**. On search, all matching to **include**
    files will be **yielded**, while all matching to
    **exclude** will be **not yielded** (ignored).

    * The ``tgbox.api._search_func`` will firstly check for \
      **include** filters, so its priority higher.

    * The ``tgbox.api._search_func`` will yield files that \
      match **all** of filters, **not** one of it.

    * The ``SearchFilter`` accepts ``list`` as kwargs \
      value. You can ``SearchFilter(id=[3,5,10])``.

    * The ``SearchFilter(**kwargs)`` will add all filters \
      to the **include**. Also use ``SearchFilter.include(...)`` \
      & ``SearchFilter.exclude(...)`` methods after initializion.

    All filters:
        * **id** *integer*: File's ID

        * **comment**   *bytes*: File's comment
        * **folder**    *bytes*: File's foldername
        * **file_name** *bytes*: File's name
        * **file_salt** *bytes*: File's salt
        * **verbyte**   *bytes*: File's version byte

        * **min_id** *integer*: File ID should be > min_id
        * **max_id** *integer*: File ID should be < max_id

        * **min_size** *integer*: File Size should be > min_size
        * **max_size** *integer*: File Size should be < max_size

        * **min_time** *integer/float*: Upload Time should be > min_time
        * **max_time** *integer/float*: Upload Time should be < max_time

        * **exported** *bool*: Yield only exported files
        * **re**       *bool*: re_search for every ``bytes`` filter
    """
    def __init__(self, **kwargs):
        self.in_filters = {
            'comment':   _TypeList(bytes),
            'folder':    _TypeList(bytes),
            'file_name': _TypeList(bytes),
            'file_salt': _TypeList(bytes),
            'verbyte':   _TypeList(bytes),   
            'id':        _TypeList(int),
            'min_id':    _TypeList(int),   
            'max_id':    _TypeList(int),  
            'min_size':  _TypeList(int), 
            'max_size':  _TypeList(int),
            'min_time':  _TypeList((int,float)),  
            'max_time':  _TypeList((int,float)), 
            'exported':  _TypeList(bool), 
            're':        _TypeList(bool), 
        }
        self.ex_filters = deepcopy(self.in_filters)
        self.include(**kwargs)
    
    def __repr__(self) -> str:
        return pformat({
            'include': self.in_filters,
            'exclude': self.ex_filters
        })
    def include(self, **kwargs) -> 'SearchFilter':
        """Will extend included filters"""
        for k,v in kwargs.items():
            if isinstance(v, list):
                self.in_filters[k].extend(v)
            else:
                self.in_filters[k].append(v)
        return self
    
    def exclude(self, **kwargs) -> 'SearchFilter':
        """Will extend excluded filters"""
        for k,v in kwargs.items():
            if isinstance(v, list):
                self.ex_filters[k].extend(v)
            else:
                self.ex_filters[k].append(v)
        return self

class CustomAttributes:
    """
    This class may be used for adding custom
    attributes to the RemoteBoxFile.

    You should attach it to the ``comment``
    kwarg of ``api.make_file`` function.

    This is part of TGBOX standart. If
    you don't need this, you can insert
    plain comments in ``api.make_file``.
    
    See issue #4 for more details.
    """
    @staticmethod
    def make(**kwargs) -> bytes:
        """
        Will make bytestring from your kwargs. 
        Please note that max comment size is
        255 bytes. See ``constants.COMMENT_MAX``.

        Kwarg must **always** be ``bytes``.

        ``make(x=5)`` is not OK, 
        ``make(x=b'\x05')`` is OK.
        """
        cattr = bytes([0xFF])
        for k,v in kwargs.items():
            cattr += bytes([len(k)]) + k.encode()
            cattr += bytes([len(v)]) + v
        return cattr
    
    @staticmethod
    def parse(cattr: bytes) -> Dict[str, bytes]:
        """
        Will parse CustomAttributes.make
        bytestring and convert it to the
        python dictionary.

        Every CustomAttributes bytestring
        must contain ``0xFF`` as first byte. 
        If not, or if error, will return ``{}``.
        """
        try:
            assert cattr[0] == 0xFF
            cattr_d, cattr = {}, cattr[1:]

            while cattr:
                key_len = cattr[0] + 1
                key = cattr[1:key_len]
                
                value_len = cattr[key_len]
                cattr = cattr[key_len:]
                
                value = cattr[1:value_len+1]
                cattr = cattr[value_len+1:]

                cattr_d[key.decode()] = value

            return cattr_d
        except:
            return {}

@dataclass
class RemoteBoxFileMetadata:
    """
    This dataclass represents ``RemoteBox``
    file metadata. After calling ``.construct()``
    method, all args will be checked, encrypted
    and assembled. You will need to add it to
    the file via ``OpenPretender.concat_metadata``.
    """
    file_name: bytes
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
        """Returns constructed metadata."""
        if not hasattr(self, '_constructed'):
            return self.construct()
        else:
            return self._constructed

    def construct(self) -> bytes:
        """Constructs and returns metadata"""
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
            PREFIX         \
          + self.verbyte   \
          + self.box_salt  \
          + self.file_salt
        )
        filedata = (
            int_to_bytes(self.size,4)                              \
          + float_to_bytes(self.duration)                          \
          + int_to_bytes(len(self.enc_foldername),2,signed=False)  \
          + self.enc_foldername                                    \
          + bytes([len(self.comment)])                             \
          + self.comment                                           \
          + int_to_bytes(len(self.file_name),2,signed=False)       \
          + self.file_name
        )
        filedata = AES(self.filekey).encrypt(filedata)
        assert len(filedata) <= FILEDATA_MAX

        if self.preview:
            preview = AES(self.filekey).encrypt(self.preview)
        else:
            preview = b''

        navbytes = int_to_bytes(len(filedata),3,signed=False) \
            + int_to_bytes(len(preview),3,signed=False)

        navbytes = AES(self.filekey).encrypt(navbytes)
        assert len(navbytes) == NAVBYTES_SIZE

        metadata += navbytes + filedata + preview
        assert len(metadata) <= METADATA_MAX
        
        self._constructed = metadata + self.file_iv
        return self._constructed

class OpenPretender:
    """
    Class to wrap Tgbox AES Generators and make it look
    like opened to "rb"-read file. 
    """
    def __init__(
            self, flo: BinaryIO, 
            aes_state: AES, 
            file_size: Optional[int] = None
        ):
        """
        Arguments:
            flo (``BinaryIO``):
                File-like object. Like ``open('file','rb')``.

            aes_state (``AESwState``):
                ``AESwState`` with Key and IV.
        """
        self._aes_state = aes_state
        self._flo = flo

        self._buffered_bytes = b''
        self._total_size = file_size
        self._position = 0

    def concat_metadata(self, metadata: RemoteBoxFileMetadata) -> None:
        """Concates metadata to the file as (metadata + file)."""
        assert len(metadata) <= METADATA_MAX

        if self._position: 
            raise ConcatError('Concat must be before any usage of object.')
        else:
            self._buffered_bytes += metadata.constructed 
    
    async def read(self, size: int=-1) -> bytes: 
        """
        Returns ``size`` bytes from async Generator.

        This function is async only because of 
        Telegram ``File`` uploading feature. You
        can use ``tgbox.sync`` in your code for reading.
        
        Arguments:
            size (``int``):
                Amount of bytes to return. By 
                default is negative (return all). 
        """
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
                chunk = self._flo.read()
                chunk = await chunk if iscoroutine(chunk) else chunk

                block = buffered + self._aes_state.encrypt(
                    chunk, pad=True, concat_iv=False)
            else:
                chunk = self._flo.read(size)
                chunk = await chunk if iscoroutine(chunk) else chunk

                if len(chunk) % 16:
                    shift = int(-(len(chunk) % 16))
                else:
                    shift = None
                
                if self._total_size <= 0 or size > self._total_size or shift != None:
                    chunk = buffered + self._aes_state.encrypt(
                        chunk, pad=True, concat_iv=False)
                else:
                    chunk = buffered + self._aes_state.encrypt(
                        chunk, pad=False, concat_iv=False)
                
                shift = size if len(chunk) > size else None
                
                if shift is not None:
                    self._buffered_bytes = chunk[shift:]

                self._total_size -= size
                block = chunk[:shift]
        
        self._position += len(block)
        return block
    
    def tell(self) -> int:
        return self._position

    def seekable(*args, **kwargs) -> bool:
        return False
    
    def close(self) -> None:
        self._stop_iteration = True

def pad_request_size(request_size: int, blocksize: int=4096) -> int:
    """
    This function pads ``request_size`` to divisible
    by 4096 bytes. If ``request_size`` < 4096, then
    it's not padded. This function designed for 
    Telethon's ``GetFileRequest``. See issue #3.
    
    .. note::
        You need to strip extra bytes from result.
    
    Arguments:
        request_size (``int``):
            Amount of requested bytes.

        blocksize (``int``, optional):
            Size of block. Typically we
            don't need to change this.
    """
    # Check amount of blocks
    block_count = request_size/blocksize
    
    if block_count <= 1:
        return request_size

    # If it's already divisible by 4096
    elif int(block_count) == block_count:
        request_size = int(block_count*blocksize)
    else:
        # Add 1 block.
        request_size = int(block_count+1)*blocksize
    
    # request_size must be divisible by 1MiB
    while 1048576 % request_size:
        request_size += 1
    return request_size

def make_folder_id(mainkey: MainKey, foldername: bytes) -> bytes:
    """
    Returns folder ID. Every folder
    has unique ID. Case-sensitive.
    
    Arguments:
        mainkey (``MainKey``):
            Your Box's mainkey.

        foldername (``bytes``):
            Folder name.
    """
    return sha256(sha256(mainkey.key).digest() + foldername).digest()[:16]

def prbg(size: int) -> bytes:
    """Will generate ``size`` pseudo-random bytes."""
    return bytes([randrange(256) for _ in range(size)])

def int_to_bytes(int_: int, length: Optional[int] = None, signed: Optional[bool] = True) -> bytes:
    """Converts int to bytes with Big byteorder."""
    length = length if length else (int_.bit_length() + 8) // 8
    return int.to_bytes(int_, length, 'big', signed=signed)

def bytes_to_int(bytes_: bytes, signed: Optional[bool] = True) -> int:
    """Converts bytes to int with Big byteorder."""
    return int.from_bytes(bytes_, 'big', signed=signed)

def float_to_bytes(float_: float) -> bytes:
    """Converts float to bytes."""
    return struct_pack('!f', float_)

def bytes_to_float(bytes_: bytes) -> float:
    """Converts bytes to float."""
    return struct_unpack('!f', bytes_)[0]

async def get_media_duration(file_path: str) -> int:
    """Returns video/audio duration with ffmpeg in seconds."""
    func = partial(subprocess_run,
        args=[FFMPEG, '-i', file_path],
        stdout=None, stderr=PIPE
    )
    try:
        loop = get_event_loop()
        stderr = (await loop.run_in_executor(None, func)).stderr
        duration = re_search(b'Duration: (.)+,', stderr).group()
        d = duration.decode().split('.')[0].split(': ')[1].split(':')
        return int(d[0]) * 60**2 + int(d[1]) * 60 + int(d[2])
    except Exception as e:
        raise DurationImpossible(f'Can\'t get media duration: {e}') from None 

async def make_media_preview(
        file_path: PathLike, 
        temp_path: Optional[PathLike] = None,
        x: int=128, y: int=-1) -> BinaryIO:
    """
    Makes x:y sized thumbnail of the 
    video/audio with ffmpeg. "-1"
    preserves one of side size.
    """
    temp_path = Path() if not temp_path else temp_path
    thumbnail_path = Path(temp_path, prbg(4).hex()+'.jpg')
    
    func = partial(subprocess_run,
        args=[
            FFMPEG, '-i', file_path, '-filter:v', f'scale={x}:{y}', '-an',
            '-loglevel', 'quiet', '-q:v', '2', thumbnail_path
        ],
        stdout=PIPE, 
        stderr=None
    )
    try:
        loop = get_event_loop()
        await loop.run_in_executor(None, func)
        thumb = BytesIO(open(thumbnail_path,'rb').read())
        remove_file(thumbnail_path); return thumb
    except Exception as e:
        # If something goes wrong then file is not created (FileNotFoundError)
        raise PreviewImpossible(f'Can\'t make thumbnail: {e}') from None

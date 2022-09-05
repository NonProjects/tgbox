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
    Optional, Dict, Generator,
    AsyncGenerator
)
from io import BytesIO
from os import PathLike
from pathlib import Path
from functools import partial
from dataclasses import dataclass
from os import remove as remove_file

from .errors import (
    ConcatError, 
    PreviewImpossible, 
    DurationImpossible
)
from .keys import FileKey, MainKey
from .crypto import AESwState as AES
from .defaults import METADATA_MAX, FFMPEG


__all__ = [
    'prbg', 'anext', 
    'SearchFilter', 
    'OpenPretender',
    'PackedAttributes'
    'int_to_bytes', 
    'bytes_to_int', 
    'get_media_duration', 
    'make_media_preview', 
    'make_image_preview',
    'ppart_id_generator'
]
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

    * The ``tgbox.tools.search_generator`` will firstly check for \
      **include** filters, so its priority higher.

    * The ``tgbox.tools.search_generator`` will yield files that \
      match **all** of filters, **not** one of it.

    * The ``SearchFilter`` accepts ``list`` as kwargs \
      value. You can ``SearchFilter(id=[3,5,10])``.

    * The ``SearchFilter(**kwargs)`` will add all filters \
      to the **include**. Also use ``SearchFilter.include(...)`` \
      & ``SearchFilter.exclude(...)`` methods after initializion.

    All filters:
        * **id** *integer*: File ID

        * **cattrs** *dict*: File CustomAttributes:
            To search for CATTRS you need to specify a dict.

            E.g: If *file* ``cattrs={b'comment': b'hi!'}``, then
            *filter* ``cattrs={b'comment': b'h'}`` will match.

            By default, ``tgbox.tools.search_generator`` will
            use an ``in``, like ``b'h' in b'hi!'``, but you
            can set a ``re`` flag to use regular expressions,
            so *filter* ``cattrs={b'comment': b'hi(.)'}`` will match.

        * **file_path** *pathlib.Path*, *str*
        * **file_name** *bytes*: File name
        * **file_salt** *bytes*: File salt
        * **verbyte**   *bytes*: File version byte

        * **min_id** *integer*: File ID should be > min_id
        * **max_id** *integer*: File ID should be < max_id

        * **min_size** *integer*: File Size should be > min_size
        * **max_size** *integer*: File Size should be < max_size

        * **min_time** *integer/float*: Upload Time should be > min_time
        * **max_time** *integer/float*: Upload Time should be < max_time

        * **mime**     *str*:  File mime type
        * **exported** *bool*: Yield only exported files
        * **re**       *bool*: re_search for every ``bytes`` 
    """
    def __init__(self, **kwargs):
        self.in_filters = {
            'cattrs':    _TypeList(dict),
            'file_path': _TypeList(str),
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
            'mime':      _TypeList(str),
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

class PackedAttributes:
    """
    This class is used to pack items to
    bytestring. We use it to pack file
    metadata as well as pack a user's
    custom attributes (cattrs), then
    encrypt it and attach to RBFile.

    We store key/value length in 3 bytes,
    so the max key/value length is 256^3-1.
    
    <key-length>key<value-length>value<...>
    """
    @staticmethod
    def pack(**kwargs) -> bytes:
        """
        Will make bytestring from your kwargs. 
        Any kwarg **always** must be ``bytes``.

        ``make(x=5)`` will not work; 
        ``make(x=b'\x05')`` is correct.

        """
        pattr = bytes([0xFF])
        for k,v in kwargs.items():
            if not isinstance(v, bytes):
                raise TypeError('Values must be bytes')

            pattr += int_to_bytes(len(k),3) + k.encode()
            pattr += int_to_bytes(len(v),3) + v
        return pattr
    
    @staticmethod
    def unpack(pattr: bytes) -> Dict[str, bytes]:
        """
        Will parse PackedAttributes.pack
        bytestring and convert it to the
        python dictionary.

        Every PackedAttributes bytestring
        must contain ``0xFF`` as first byte. 
        If not, or if error, will return ``{}``.
        """
        if not pattr:
            return {}
        try:
            assert pattr[0] == 0xFF
            pattr_d, pattr = {}, pattr[1:]

            while pattr:
                key_len = bytes_to_int(pattr[:3])
                key = pattr[3:key_len+3]
                
                value_len = bytes_to_int(pattr[key_len+3:key_len+6])
                pattr = pattr[key_len+6:]

                if value_len:
                    value = pattr[:value_len]
                    pattr = pattr[value_len:]
                else:
                    value = b''

                pattr_d[key.decode()] = value

            return pattr_d
        except:
            return {}

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

    def concat_metadata(self, metadata: bytes) -> None:
        """Concates metadata to the file as (metadata + file)."""
        assert len(metadata) <= METADATA_MAX

        if self._position: 
            raise ConcatError('Concat must be before any usage of object.')
        else:
            self._buffered_bytes += metadata
    
    async def read(self, size: int=-1) -> bytes: 
        """
        Returns ``size`` bytes from async Generator.

        This method is async only because we use
        ``File`` uploading from the async library. You
        can use ``tgbox.sync`` in your sync code for reading.
        
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

def pad_request_size(request_size: int, bsize: int=4096) -> int:
    """
    This function pads ``request_size`` to divisible
    by BSIZE bytes. If ``request_size`` < BSIZE, then
    it's not padded. This function designed for Telethon's 
    ``GetFileRequest``. See issue #3 on TGBOX GitHub.
    
    .. note::
        You will need to strip extra bytes from result, as
        request_size can be bigger than bytecount you want.
    
    Arguments:
        request_size (``int``):
            Amount of requested bytes,
            max is 1048576 (1MiB).

        bsize (``int``, optional):
            Size of block. Typically we
            don't need to change this.
    """
    assert request_size <= 1048576, 'Max 1MiB'

    if request_size <= bsize:
        return request_size

    while 1048576 % request_size:
        request_size = ((request_size + bsize) // bsize) * bsize 
    return request_size

def ppart_id_generator(path: Path, mainkey: MainKey) -> Generator[tuple, None, None]:
    """
    This generator will iterate over path parts and
    yield their unique IDs. We will use this to better
    navigate over *abstract* Folders in the LocalBox.

    The path **shouldn't** contain a file name,
    otherwise directory will contain it as folder.

    */home/user/* is **OK**
    */home/user/file.txt* is **NOT**

    Will yield a tuple (PART, PARENT_PART_ID, PART_ID)
    """
    parent_part_id = b'' # The root (/ anchor) doesn't have parent
    for part in path.parts:
        part_id = sha256(
            mainkey\
          + sha256(part.encode()).digest()\
          + parent_part_id
        )
        yield (part, parent_part_id, part_id.digest())
        parent_part_id = part_id.digest()

def prbg(size: int) -> bytes:
    """Will generate ``size`` pseudo-random bytes."""
    return bytes([randrange(256) for _ in range(size)])

def int_to_bytes(
        int_: int, length: Optional[int] = None, 
        signed: Optional[bool] = False) -> bytes:

    """Converts int to bytes with Big byteorder."""

    bit_length = int_.bit_length()

    if not length:
        if signed and not (int_ >= -128 and int_ <= 127):
            divide_with = 16
        else:
            divide_with = 8
        
        bit_length = ((bit_length + divide_with) // divide_with)
        length = (bit_length * divide_with) // 8

    return int.to_bytes(int_, length, 'big', signed=signed)

def bytes_to_int(bytes_: bytes, signed: Optional[bool] = False) -> int:
    """Converts bytes to int with Big byteorder."""
    return int.from_bytes(bytes_, 'big', signed=signed)

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

async def search_generator(
        sf: SearchFilter, 
        ta = None, # Optional[TelegramAccount]
        mainkey: Optional[MainKey] = None,
        it_messages: Optional[AsyncGenerator] = None,
        lb = None) -> AsyncGenerator:
    """
    Generator used to search for files in dlb and rb. It's
    only for internal use, and you shouldn't use it in your
    own projects. ``ta`` must be specified with ``it_messages``.
    
    If file is imported from other RemoteBox and was exported
    to your LocalBox, then you can specify box as ``lb``. AsyncGenerator
    will try to get ``FileKey`` and decrypt ``EncryptedRemoteBoxFile``.
    Otherwise imported file will be ignored.
    """
    in_func = re_search if sf.in_filters['re'] else lambda p,s: p in s

    if it_messages:
        iter_from = it_messages
    else:
        min_id = sf.in_filters['min_id'][-1] if sf.in_filters['min_id'] else None
        max_id = sf.in_filters['max_id'][-1] if sf.in_filters['max_id'] else None
        iter_from = lb.files(min_id=min_id, max_id=max_id)
    
    if not iter_from:
        raise ValueError('At least it_messages or lb must be specified.')
    
    async for file in iter_from:
        if hasattr(file,'document') and file.document: 
            try:
                file = await EncryptedRemoteBoxFile(file, ta).init() 

                if hasattr(lb, '_mainkey') and not mainkey: 
                    if isinstance(lb._mainkey, EncryptedMainkey):
                        mainkey = None
                    else:
                        mainkey = lb._mainkey

                file = file if not mainkey else await file.decrypt(mainkey)

            except ValueError: # Incorrect padding. Imported file?
                if lb and isinstance(lb, DecryptedLocalBox):
                    try:
                        dlbfi = await lb.get_file(file.id, cache_preview=False)
                    # Mostly, it's not a Tgbox file, so continue.
                    except BrokenDatabase: 
                        continue

                    if not dlbfi: 
                        continue
                    else:
                        file = await file.decrypt(dlbfi._filekey)
                else:
                    continue
        
        if hasattr(file, '_message'): # *RemoteBoxFile
            file_size = file.file_size
        elif hasattr(file, '_tgbox_db'): # *LocalBoxFile
            file_size = file.size
        else:
            continue
        
        # We will use it as flags, the first
        # is for 'include', the second is for
        # 'exclude'. Both should be True to
        # match SearchFilter filters.
        yield_result = [True, True]

        for indx, filter in enumerate((sf.in_filters, sf.ex_filters)):
            if filter['exported']:
                if bool(file.exported) != bool(filter['exported']): 
                    if indx == 0: # O is Include
                        yield_result[indx] = False
                        break

                elif bool(file.exported) == bool(filter['exported']): 
                    if indx == 1: # 1 is Exclude
                        yield_result[indx] = False
                        break

            for mime in filter['mime']:
                if in_func(mime, file.mime):
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['mime']:
                    if indx == 0:
                        yield_result[indx] = False
                        break
            
            if filter['min_time']:
                if file.upload_time < filter['min_time'][-1]:
                    if indx == 0:
                        yield_result[indx] = False
                        break

                elif file.upload_time >= filter['min_time'][-1]:
                    if indx == 1:
                        yield_result[indx] = False
                        break

            if filter['max_time']:
                if file.upload_time > filter['max_time'][-1]: 
                    if indx == 0:
                        yield_result[indx] = False
                        break

                elif file.upload_time <= filter['max_time'][-1]: 
                    if indx == 1:
                        yield_result[indx] = False
                        break

            if filter['min_size']:
                if file_size < filter['min_size'][-1]:
                    if indx == 0:
                        yield_result[indx] = False
                        break

                elif file_size >= filter['min_size'][-1]:
                    if indx == 1:
                        yield_result[indx] = False
                        break

            if filter['max_size']:
                if file_size > filter['max_size'][-1]: 
                    if indx == 0:
                        yield_result[indx] = False
                        break

                elif file_size <= filter['max_size'][-1]: 
                    if indx == 1:
                        yield_result[indx] = False
                        break

            if filter['min_id']:
                if file.id < filter['min_id'][-1]: 
                    if indx == 0:
                        yield_result[indx] = False
                        break

                elif file.id >= filter['min_id'][-1]: 
                    if indx == 1:
                        yield_result[indx] = False
                        break

            if filter['max_id']:
                if file.id > filter['max_id'][-1]: 
                    if indx == 0:
                        yield_result[indx] = False
                        break

                elif file.id <= filter['max_id'][-1]: 
                    if indx == 1:
                        yield_result[indx] = False
                        break
            
            for id in filter['id']:
                if file.id == id:
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['id']:
                    if indx == 0:
                        yield_result[indx] = False
                        break
            
            if hasattr(file, '_cattrs'):
                for cattr in filter['cattrs']:
                    for k,v in cattr.items():
                        if k in file.cattrs:
                            if in_func(v, file.cattrs[k]):
                                if indx == 1:
                                    yield_result[indx] = False
                                break
                    else:
                        if filter['cattrs']:
                            if indx == 0:
                                yield_result[indx] = False
                                break
            
            for file_path in filter['file_path']:
                if in_func(str(file_path), str(file.file_path)):
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['file_path']:
                    if indx == 0:
                        yield_result[indx] = False
                        break

            for file_name in filter['file_name']:
                if in_func(file_name, file.file_name):
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['file_name']:
                    if indx == 0:
                        yield_result[indx] = False
                        break

            for file_salt in filter['file_salt']:
                if in_func(file_salt, file.file_salt):
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['file_salt']:
                    if indx == 0:
                        yield_result[indx] = False
                        break

            for verbyte in filter['verbyte']:
                if verbyte == file.verbyte:
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['verbyte']:
                    if indx == 0:
                        yield_result[indx] = False
                        break
        
        if all(yield_result):
            yield file
        else:
            continue

"""This module stores utils required by API."""

from asyncio import (
    iscoroutine, get_event_loop
)
from copy import deepcopy
from pprint import pformat
from hashlib import sha256
from random import randrange

from typing import (
    BinaryIO, Optional, Dict,
    Generator, Union
)
from subprocess import PIPE, run as subprocess_run

from io import BytesIO
from os import PathLike
from functools import partial

from re import search as re_search
from os import remove as remove_file

from platform import system as platform_system
from pathlib import PureWindowsPath, Path

from .errors import (
    ConcatError,
    PreviewImpossible,
    DurationImpossible
)
from .defaults import FFMPEG
from .keys import FileKey, MainKey
from .crypto import AESwState as AES

__all__ = [
    'prbg', 'anext',
    'SearchFilter',
    'OpenPretender',
    'PackedAttributes',
    'int_to_bytes',
    'bytes_to_int',
    'get_media_duration',
    'make_media_preview',
    'ppart_id_generator',
    'make_general_path',
    'guess_path_type',
    'make_safe_file_path'
]

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

    def __len__(self):
        return len(self.list)

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
            for type_ in self.type:
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
      & ``SearchFilter.exclude(...)`` methods after initialization.

    All filters:
        * **scope** *str*: Define a path as search scope:
            The *scope* is an absolute directory in which
            we will search your file by other *filters*. By
            default, the ``tgbox.api.utils.search_generator``
            will search over the entire *LocalBox*. This can
            be slow if you're have too many files.

            **Example**: let's imagine that You're a Linux user which
            share it's *Box* with the Windows user. In this case,
            Your *LocalBox* will contain a path parts on the
            ``'/'`` (Linux) and ``'C:\\'`` (Windows) roots. If You
            know that some file was uploaded by Your friend,
            then You can specify a ``scope='C:\\'`` to ignore
            all files uploaded from the Linux machine. This
            will significantly fasten the search process,
            because almost all filters require to select
            row from the LocalBox DB, decrypt Metadata and
            compare its values with ones from ``SearchFilter``.

            | !: The ``scope`` will be ignored on *RemoteBox* search.
            | !: The ``min_id`` & ``max_id`` will be ignored if ``scope`` used.

        * **id** *integer*: File ID

        * **cattrs** *dict*: File CustomAttributes:
            To search for CATTRS you need to specify a dict.

            E.g: If *file* ``cattrs={b'comment': b'hi!'}``, then
            *filter* ``cattrs={b'comment': b'h'}`` will match.

            By default, ``tgbox.api.utils.search_generator`` will
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
        * **imported** *bool*: Yield only imported files
        * **re**       *bool*: re_search for every ``bytes``
    """
    def __init__(self, **kwargs):
        self.in_filters = {
            'scope':     _TypeList(str),
            'cattrs':    _TypeList(dict),
            'file_path': _TypeList(str),
            'file_name': _TypeList(str),
            'file_salt': _TypeList((bytes,str)),
            'verbyte':   _TypeList(bytes),
            'id':        _TypeList(int),
            'min_id':    _TypeList(int),
            'max_id':    _TypeList(int),
            'min_size':  _TypeList(int),
            'max_size':  _TypeList(int),
            'min_time':  _TypeList((int,float)),
            'max_time':  _TypeList((int,float)),
            'mime':      _TypeList(str),
            'imported':  _TypeList(bool),
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
        self._stop_iteration = False

        self._position = 0

    def concat_metadata(self, metadata: bytes) -> None:
        """Concates metadata to the file as (metadata + file)."""
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
        if self._stop_iteration:
            raise Exception('Stream was closed')

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

    def seekable(self, *args, **kwargs) -> bool:
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

def guess_path_type(path: Union[str, Path]) -> str:
    """
    This function will try to guess file path
    type. It can be Windows-like or Unix-like

    Returns 'windows' or 'unix'
    """
    if PureWindowsPath(path).drive:
        return 'windows'
    return 'unix'

def make_general_path(path: Union[str, Path]) -> Path:
    """
    This function will make a valid
    UNIX-like Path from the Windows-like
    on the UNIX-like systems.
    """
    # Windows can support UNIX-like paths
    if platform_system().lower() == 'windows':
        return Path(path) if isinstance(path, str) else path

    path = path if isinstance(path, str) else str(path)

    if (win_path := PureWindowsPath(path)).drive:
        return Path(*win_path.parts)

    return Path(path)

def make_safe_file_path(path: Union[str, Path]) -> Path:
    """
    This function will make a safe file path (a
    file path that can be easily inserted into
    another path). This is mostly for internal
    purposes, i.e ``DecryptedRemoteBox.download()``

    This function will make a
        @/home/non/test from /home/non/test
        C\\Users\\non\\test from C:\\Users\\non\\test

    ...so this path can be easily inserted into
    another, i.e DownloadsTGBOX/@/home/non/test

    ``path`` *must* be absolute.
    """
    path_type = guess_path_type(path)
    path = make_general_path(path)

    if path_type == 'unix':
        # /home/non -> @/home/non
        if str(path)[0] == '/':
            return Path(str(path).replace('/','@/',1))
        else:
            return Path(str(path).replace('\\','@\\',1))

    elif path_type == 'windows':
        # C:\Users\user -> C\Users\User
        drive_letter = path.parts[0][0]
        return Path(drive_letter, *path.parts[1:])

async def anext(aiterator, default=...):
    """Analogue to Python 3.10+ anext()"""
    try:
        return await aiterator.__anext__()
    except StopAsyncIteration as e:
        if default is not Ellipsis:
            return default
        raise e

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

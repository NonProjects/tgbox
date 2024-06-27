"""This module stores utils required by API."""

import logging

from asyncio import (
    iscoroutine, get_event_loop
)
from copy import deepcopy
from pprint import pformat
from hashlib import sha256
from random import Random

from typing import (
    BinaryIO, Optional, Dict,
    Generator, Union
)
from subprocess import PIPE, run as subprocess_run

from io import BytesIO
from functools import partial

from os import urandom, PathLike
try:
    # Try to use Third-party Regex if installed
    from regex import search as re_search
except ImportError:
    from re import search as re_search

from platform import system as platform_system
from pathlib import PureWindowsPath, PurePosixPath, Path

from .errors import (
    ConcatError,
    PreviewImpossible,
    DurationImpossible
)
from .defaults import FFMPEG

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
    'make_safe_file_path',
    'make_file_fingerprint'
]
logger = logging.getLogger(__name__)

class _TypeList:
    """
    This is small version of ``list()`` that
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
        * **file_name** *str*: File name
        * **file_salt** *bytes/str*: File salt
        * **verbyte**   *bytes*: File version byte
        * **mime**      *str*: File mime type

        * **minor_version** *integer*: File minor version

        * **min_id** *integer*: File ID should be > min_id
        * **max_id** *integer*: File ID should be < max_id

        * **min_size** *integer*: File Size should be > min_size
        * **max_size** *integer*: File Size should be < max_size

        * **min_time** *integer/float*: Upload Time should be > min_time
        * **max_time** *integer/float*: Upload Time should be < max_time

        * **re**                  *bool*: re_search for every ``bytes``
        * **imported**            *bool*: Yield only imported files
        * **non_recursive_scope** *bool*: Disable recursive scope search
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
            'minor_version': _TypeList(int),
            'non_recursive_scope': _TypeList(bool),
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

    Every key/value will be randomly
    shuffled on the packing process.
    """
    @staticmethod
    def pack(
         *, random_seed: Optional[bytes] = None,
            protected_keys: Optional[tuple] = None,
            **kwargs) -> bytes:
        """
        Will make bytestring from your kwargs.
        Any kwarg **always** must be ``bytes``.

        ``make(x=5)`` will not work;
        ``make(x=b'\x05')`` is correct.

        We shuffle all key/value before packing, so
        you can specify ``random_seed``. Otherwise,
        ``urandom(32)`` will be used instead.

        Keys specified in the ``protect_key``
        tuple will *never* be in the start or
        or in the end of the packed bytestring.

        ``protect_key`` is for internal usage.
        """
        # We randomize all keys before packing
        random = Random(random_seed or urandom(32))

        rnd_keys = list(kwargs.keys())
        random.shuffle(rnd_keys)

        for pkey in protected_keys or ():
            _check = (
                rnd_keys.index(pkey) == 0, # Start
                rnd_keys.index(pkey) == (len(rnd_keys) - 1) # End
            )
            if any(_check):
                rnd_keys.pop(rnd_keys.index(pkey))
                rnd_keys.insert(len(rnd_keys) // 2, pkey)

        pattr = bytes([0xFF])
        for k in rnd_keys:
            if not isinstance(kwargs[k], bytes):
                raise TypeError('Values must be bytes')

            pattr += int_to_bytes(len(k), 3) + k.encode()
            pattr += int_to_bytes(len(kwargs[k]), 3) + kwargs[k]
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
            aes_state: 'tgbox.crypto.AESwState',
            hmac_state: 'hashlib.HMAC',
            file_size: Optional[int] = None,
        ):
        """
        Arguments:
            flo (``BinaryIO``):
                File-like object. Like ``open('file','rb')``.

            aes_state (``AESwState``):
                ``AESwState`` with Key and IV.

            hmac_state (``hmac.HMAC``):
                ``HMAC`` initialized with ``HMACKey``

            file_size (``int``, optional):
                File size of ``flo``. If not specified,
                we will try to seek.
        """
        self._aes_state = aes_state
        self._hmac_state = hmac_state
        self._flo = flo

        self._file_size = file_size
        self._current_size = file_size

        self._buffered_bytes = b''
        self._stop_iteration = False

        self._hmac_returned = False
        self._padding_added = False

        self._concated_metadata_size = None
        self._position = 0

    def __repr__(self):
        return (
            f'''<class {self.__class__.__name__}({self._flo}, {repr(self._aes_state)}, '''
            f'''{self._current_size})>'''
        )
    def __str__(self):
        return (
            f'''<class {self.__class__.__name__}({self._flo}, {repr(self._aes_state)}, '''
            f'''{self._current_size})> # {self._position=}, {len(self._buffered_bytes)=}'''
        )
    def concat_metadata(self, metadata: bytes) -> None:
        """Concates metadata to the file as (metadata + file)."""
        if self._position:
            raise ConcatError('Concat must be before any usage of object.')
        else:
            self._buffered_bytes += metadata
            self._concated_metadata_size = len(metadata)

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

        if size % 16 or size < 64 and not size == -1:
            raise ValueError(
                'size must be -1 (return all), or >= 64, divisible by 16'
            )
        if self._current_size is None:
            self._current_size = self._flo.seek(0,2) # Move to file end
            self._flo.seek(0,0) # Move to file start
            self._current_size += len(self._buffered_bytes)

        self._current_size -= size

        if size < 0 or self._current_size < 0:
            self._current_size = 0

        if (self._current_size == 0 and self._padding_added)\
            or (size <= len(self._buffered_bytes) and size != -1):
                if self._hmac_returned:
                    return b''

                elif self._current_size == 0:
                    if len(self._buffered_bytes) + 32 < size: # + 32 is HMAC
                        block = self._buffered_bytes + self._hmac_state.digest()
                        self._buffered_bytes = b''
                        self._hmac_returned = True
                    else:
                        block = self._buffered_bytes[:size]
                        self._buffered_bytes = self._buffered_bytes[size:]
                else:
                    block = self._buffered_bytes[:size]
                    self._buffered_bytes = self._buffered_bytes[size:]
        else:
            buffered = self._buffered_bytes
            self._buffered_bytes = b''

            if size == -1:
                chunk = self._flo.read()
                chunk = await chunk if iscoroutine(chunk) else chunk

                logger.debug(f'Trying to read all bytes, got {len(chunk)=}')

                self._hmac_state.update(chunk)

                block = buffered + self._aes_state.encrypt(
                    chunk, pad=True, concat_iv=False)

                block += self._hmac_state.digest()
                self._hmac_returned = True
                self._padding_added = True
            else:
                chunk = self._flo.read(size)
                chunk = await chunk if iscoroutine(chunk) else chunk

                logger.debug(f'Trying to read {size=}, got {len(chunk)=}')

                self._hmac_state.update(chunk)

                if len(chunk) < size:
                    chunk = buffered + self._aes_state.encrypt(
                        chunk, pad=True, concat_iv=False)

                    self._padding_added = True
                else:
                    chunk = buffered + self._aes_state.encrypt(
                        chunk, pad=False, concat_iv=False)

                if len(chunk) > size:
                    shift = size
                else:
                    shift = None

                if shift is not None:
                    self._buffered_bytes = chunk[shift:]

                block = chunk[:shift]

        logger.debug(f'Return {len(block)=}; {self._current_size=}')

        self._position += len(block)
        return block

    def tell(self) -> int:
        return self._position

    def seekable(self, *args, **kwargs) -> bool: # pylint: disable=unused-argument
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

def ppart_id_generator(path: Path, mainkey: 'MainKey') -> Generator[tuple, None, None]:
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
    if guess_path_type(path) == 'unix':
        path = str(PurePosixPath(path))
        path = PurePosixPath(path.lstrip('\\'))
    else:
        path = PureWindowsPath(path)

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
    random = Random()
    return bytes([random.randrange(256) for _ in range(size)])

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

    # If path has Letter drive (i.e C:) then it's
    # definitely a Windows-like path
    if (win_path := PureWindowsPath(path)).drive:
        return Path(*win_path.parts)

    # If user specified 'path' is the same as converted
    # to pathlib.Path (contains only one part) it means
    # that it's most probably a Windows path that
    # doesn't have drive letter.
    if str(path) == Path(path).parts[0]:
        return Path(*PureWindowsPath(path).parts)

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

def make_file_fingerprint(mainkey: 'MainKey', file_path: Union[str, Path]) -> bytes:
    """
    Function to make a file Fingerprint.

    Fingerprint is a SHA256 over ``mainkey`` and
    ``file_path``, not a hash of a file itself
    in any form. We use it to check if prepared
    file is unique or not (and raise error).

    Arguments:
        mainkey (``MainKey``):
            The ``MainKey`` of your *Box*

        file_path (``Union[str, Path]``):
            A file path from which we will make a
            Fingerprint. It **should** include a
            file name!

            /home/xxx/ (directory) is NOT OK!
            /home/xxx/file.txt (file) is OK!
    """
    return sha256(str(file_path).encode() + mainkey.key).digest()

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
        raise DurationImpossible(f'Can\'t get media duration: {e}')

async def make_media_preview(file_path: PathLike, x: int=128, y: int=-1) -> BinaryIO:
    """
    Makes x:y sized thumbnail of the video/audio
    with ffmpeg. "-1" preserves one of side size.
    """
    sp_func = partial(subprocess_run,
        args=[
            FFMPEG, '-i', file_path, '-frames:v', '1', '-filter:v', f'scale={x}:{y}',
            '-an', '-loglevel', 'quiet', '-q:v', '2', '-f', 'mjpeg', 'pipe:1'
        ],
        capture_output = True
    )
    loop = get_event_loop()
    try:
        sp_result = await loop.run_in_executor(None, sp_func)
        assert sp_result.stdout, 'Preview bytes is empty'
        return BytesIO(sp_result.stdout)
    except Exception as e:
        raise PreviewImpossible(f'Can\'t make thumbnail: {e}')

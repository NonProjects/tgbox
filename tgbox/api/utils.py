"""Module with utils for api package."""

import logging

from typing import (
    BinaryIO, Optional,
    Union, AsyncGenerator
)
from os import PathLike
from dataclasses import dataclass

try:
    # Try to use Third-party Regex if installed
    from regex import search as re_search
except ImportError:
    from re import search as re_search

from base64 import urlsafe_b64encode

from asyncio import get_event_loop_policy, get_running_loop

from inspect import (
    iscoroutinefunction, isasyncgenfunction, isasyncgen
)
from functools import wraps

from telethon.tl.custom.file import File
from telethon.sessions import StringSession

from telethon.tl.types import Photo, Document
from telethon.tl.types.auth import SentCode

from telethon import TelegramClient as TTelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.tl.functions.auth import ResendCodeRequest


from ..defaults import VERSION
from ..fastelethon import download_file
from ..tools import anext, SearchFilter, _TypeList

from .db import TABLES, TgboxDB


__all__ = [
    'search_generator',
    'DirectoryRoot',
    'PreparedFile',
    'TelegramClient',
    'DefaultsTableWrapper',
    'RemoteBoxDefaults'
]
logger = logging.getLogger(__name__)

class TelegramClient(TTelegramClient):
    """
    A little extension to the ``telethon.TelegramClient``.

    This class inherits Telethon's TelegramClient and support
    all features that has ``telethon.TelegramClient``.

    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import TelegramClient, make_remotebox
        from getpass import getpass # For hidden input

        PHONE_NUMBER = '+10000000000' # Your phone number
        API_ID = 1234567 # Your API_ID: https://my.telegram.org
        API_HASH = '00000000000000000000000000000000' # Your API_HASH

        async def main():
            tc = TelegramClient(
                phone_number = PHONE_NUMBER,
                api_id = API_ID,
                api_hash = API_HASH
            )
            await tc.connect()
            await tc.send_code()

            await tc.log_in(
                code = int(input('Code: ')),
                password = getpass('Pass: ')
            )
            erb = await make_remotebox(tc)

        asyncio_run(main())
    """
    __version__ = VERSION

    def __init__(
            self, api_id: int, api_hash: str,
            phone_number: Optional[str] = None,
            session: Optional[Union[str, StringSession]] = None,
            **kwargs) -> None:
        """
        .. note::
            You should specify at least ``session`` or ``phone_number``.

        Arguments:
            api_id (``int``):
                API_ID from https://my.telegram.org.

            api_hash (``int``):
                API_HASH from https://my.telegram.org.

            phone_number (``str``, optional):
                Phone number linked to your Telegram
                account. You may want to specify it
                to recieve log-in code. You should
                specify it if ``session`` is ``None``.

            session (``str``, ``StringSession``, optional):
                ``StringSession`` that give access to
                your Telegram account. You can get it
                after connecting and signing in via
                ``TelegramClient.session.save()`` method.

        ..note::
            You can use ``.start()`` method on ``TelegramClient``
            without specifying ``phone_number`` or ``session``,
            otherwise ``phone_number`` OR ``session`` is required.

        ..tip::
            This ``TelegramClient`` support all keyword
            arguments (**kwargs) that support parent
            ``telethon.TelegramClient`` object.
        """
        super().__init__(
            StringSession(session),
            api_id, api_hash, **kwargs
        )
        self._api_id, self._api_hash = api_id, api_hash
        self._phone_number, self._session = phone_number, session

    def __check_session_phone_number(self):
        if not self._session and not self._phone_number:
            raise ValueError(
                'You should set at least "session" or "phone_number".'
            )

    def set_phone_number(self, phone_number: str) -> None:
        """Use this function if you didn't
        specified ``phone_number`` on init.
        """
        self._phone_number = phone_number

    def set_session(self, session: Union[str, StringSession]) -> None:
        """Use this function if you didn't
        specified ``session`` on init.
        """
        self._session = session

    async def send_code(self, force_sms: Optional[bool]=False) -> SentCode:
        """
        Sends the Telegram code needed to login to the given phone number.

        Arguments:
            force_sms (``bool``, optional):
                Whether to force sending as SMS.
        """
        self.__check_session_phone_number()
        logger.info(f'Sending login code to {self._phone_number}...')

        return await self.send_code_request(
            self._phone_number, force_sms=force_sms
        )
    async def log_in(
            self, password: Optional[str] = None,
            code: Optional[Union[int,str]] = None) -> None:
        """
        Logs in to Telegram to an existing user account.
        You should only use this if you are not signed in yet.

        Arguments:
            password (``str``, optional):
                Your 2FA password. You can ignore
                this if you don't enabled it yet.

            code (``int``, optional):
                The code that Telegram sent you after calling
                ``TelegramClient.send_code()`` method.
        """
        self.__check_session_phone_number()

        if not await self.is_user_authorized():
            try:
                logger.info(f'Trying to sign-in with {self._phone_number} and {code} code..')
                await self.sign_in(self._phone_number, code)
            except SessionPasswordNeededError:
                logger.info(
                    '''Log-in without 2FA password failed. '''
                   f'''Trying to sign-in with {self._phone_number}, '''
                   f'''password and {code} code..'''
                )
                await self.sign_in(password=password)
        else:
            logger.debug(f'User {self._phone_number} is already authorized.')

    async def resend_code(self, sent_code: SentCode) -> SentCode:
        """
        Will send you login code again. This can be used to
        force Telegram send you SMS or Call to dictate code.

        Arguments:
            sent_code (``SentCode``):
                Result of the ``tc.send_code`` or
                result of the ``tc.resend_code`` method.

        Example:

        .. code-block:: python

            tc = tgbox.api.TelegramClient(...)
            sent_code = await tc.send_code()
            sent_code = await tc.resend_code(sent_code)
        """
        self.__check_session_phone_number()

        logger.info(f'Resending login code to {self._phone_number}...')
        return await self(ResendCodeRequest(
            self._phone_number, sent_code.phone_code_hash)
        )

class TelegramVirtualFile:
    """
    You can use this class for re-upload to RemoteBox
    files that already was uploaded to any other
    Telegram chat. Wrap it over ``Document`` and
    specify in the ``DecryptedLocalBox.prepare_file``
    """
    def __init__(self, document: Union[Photo, Document], tc: TelegramClient):
        self.tc = tc
        self.document = document

        file = File(document)

        self.name = file.name
        self.size = file.size
        self.mime = file.mime_type

        self.duration = file.duration\
            if file.duration else 0

        self._downloader = None

    def __repr__(self) -> str:
        return (
            f'''<class {self.__class__.__name__} @ '''
            f'''{self.name=}, {self.size=}, {self.mime=}>'''
        )
    async def get_preview(self, quality: int=1) -> bytes:
        if hasattr(self.document,'sizes')\
            and not self.document.sizes:
                return b''

        if hasattr(self.document,'thumbs')\
            and not self.document.thumbs:
                return b''

        return await self.tc.download_media(
            message = self.document,
            thumb = quality, file = bytes
        )
    async def read(self, size: int=-1) -> bytes: # pylint: disable=unused-argument
        """Will return <= 512KiB of data. 'size' ignored"""
        if not self._downloader:
            self._downloader = download_file(
                self.tc, self.document
            )
        chunk = await anext(self._downloader)
        return chunk

@dataclass
class PreparedFile:
    """
    This dataclass store data needed for upload
    by ``DecryptedRemoteBox.push_file`` in future.

    Usually it's only for internal use.
    """
    dlb: 'tgbox.api.local.DecryptedLocalBox'
    file: BinaryIO
    filekey: 'tgbox.keys.FileKey'
    filesize: int
    filepath: PathLike
    filesalt: 'tgbox.crypto.FileSalt'
    hmackey: 'tgbox.keys.HMACKey'
    fingerprint: bytes
    metadata: bytes
    imported: bool

    def set_file_id(self, id: int):
        """You should set ID after pushing to remote"""
        self.file_id = id

    def set_upload_time(self, upload_time: int):
        """You should set time after pushing to remote"""
        self.upload_time = upload_time

    def set_updated_enc_metadata(self, ue_metadata: bytes):
        """
        If user requested to update some already pushed
        to Remote file AND if target file HAS Updated
        Encrypted Metadata in caption then we need to
        re-encrypt it with a new filekey and attach here.

        This is for internal usage, you can ignore it.
        """
        self.updated_enc_metadata = ue_metadata

class DirectoryRoot:
    """
    Type used to specify that you want to
    access absolute local directory root.

    This class doesn't have any methods,
    please use it only for ``lbd.iterdir``
    """

async def search_generator(
        sf: SearchFilter, it_messages: Optional[AsyncGenerator] = None,
        lb: Optional['tgbox.api.local.DecryptedLocalBox'] = None,
        cache_preview: bool=True, reverse: bool=False,
        fetch_count: Optional[int] = 100,
        erase_encrypted_metadata: bool=True) -> AsyncGenerator:
    """
    Generator used to search for files in dlb and rb. It's
    only for internal use and you shouldn't use it in your
    own projects.

    If file is exported from other RemoteBox and was imported to your
    LocalBox, then you can specify ``dlb`` as ``lb``. AsyncGenerator
    will try to get ``FileKey`` and decrypt ``EncryptedRemoteBoxFile``.
    Otherwise imported file will be ignored.
    """
    in_func = re_search if sf.in_filters['re'] else lambda p,s: p in s

    if it_messages:
        iter_from = it_messages

    elif any((sf.in_filters['scope'], sf.ex_filters['scope'])):
        if not sf.in_filters['scope']:
            lbf = await anext(lb.files(), None)
            if not lbf: return # Local doesn't have files

        async def scope_generator(scope: Union[str, list]):
            scope = scope if scope else DirectoryRoot
            scope = scope if isinstance(scope, _TypeList) else [scope]

            for current_scope in scope:
                if current_scope is DirectoryRoot:
                    iterdir = lbf.directory.iterdir(ppid=current_scope)

                elif hasattr(current_scope, '_part_id'):
                    iterdir = current_scope.iterdir()
                else:
                    iterdir = await lb.get_directory(current_scope)
                    if not iterdir:
                        return
                    iterdir = iterdir.iterdir()

                async for content in iterdir:
                    if hasattr(content, '_part_id'):
                        # This is DecryptedLocalBoxDirectory

                        if sf.ex_filters['scope'] or sf.in_filters['non_recursive_scope']:
                            await content.lload(full=True)

                        if str(content) in sf.ex_filters['scope']\
                            or sf.in_filters['non_recursive_scope']:
                                continue # This directory is excluded

                        async for dlbf in scope_generator(content):
                            yield dlbf # This is DecryptedLocalBoxFile
                    else:
                        yield content # This is DecryptedLocalBoxFile

        iter_from = scope_generator(sf.in_filters['scope'])
    else:
        min_id = sf.in_filters['min_id'][-1]\
            if sf.in_filters['min_id'] else None

        max_id = sf.in_filters['max_id'][-1]\
            if sf.in_filters['max_id'] else None

        iter_from = lb.files(
            min_id = min_id,
            max_id = max_id,
            ids = sf.in_filters['id'],
            cache_preview = cache_preview,
            reverse = reverse,
            fetch_count=fetch_count,
            erase_encrypted_metadata=erase_encrypted_metadata
        )
        if not isasyncgen(iter_from):
            # The .files() generator was syncified, so we can't
            # use the "async for" on it. We will make a little wrapper
            async def _async_iter_from(_iter_from):
                try:
                    while True:
                        yield await next(_iter_from)
                except StopAsyncIteration:
                    return

            iter_from = _async_iter_from(iter_from)

    if not iter_from:
        raise ValueError('At least it_messages or lb must be specified.')

    async for file in iter_from:
        if hasattr(file, '_rb'): # *RemoteBoxFile
            file_size = file.file_size

        elif hasattr(file, '_lb'): # *LocalBoxFile
            file_size = file.size
        else:
            continue

        if hasattr(file, 'file_path') and file.file_path:
            file_path = str(file.file_path)
        else:
            file_path = ''

        # We will use it as flags, the first
        # is for 'include', the second is for
        # 'exclude'. Both should be True to
        # match SearchFilter filters.
        yield_result = [True, True]

        for indx, filter in enumerate((sf.in_filters, sf.ex_filters)):
            if filter['imported']:
                if bool(file.imported) != bool(filter['imported']):
                    if indx == 0: # O is Include
                        yield_result[indx] = False
                        break

                elif bool(file.imported) == bool(filter['imported']):
                    if indx == 1: # 1 is Exclude
                        yield_result[indx] = False
                        break

            for minor_version in filter['minor_version']:
                if minor_version == file.minor_version:
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if filter['minor_version']:
                    if indx == 0:
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

            # If it_messages is specified, then we're making search
            # on the RemoteBox, thus, we can't use the "scope" filter,
            # which is LocalBox-only; so we will treat it as the
            # simple "file_path" filter to mimic "scope".
            if it_messages:
                sf_file_path = [*filter['file_path'], *filter['scope']]
            else:
                sf_file_path = filter['file_path']

            for filter_file_path in sf_file_path:
                if in_func(str(filter_file_path), file_path):
                    if indx == 1:
                        yield_result[indx] = False
                    break
            else:
                if sf_file_path:
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
                if isinstance(file_salt, str):
                    fsalt = urlsafe_b64encode(file.file_salt.salt).decode()
                else:
                    fsalt = file.file_salt

                if in_func(file_salt, fsalt):
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
            logger.debug(f'SearchFilter matched ID{file.id}')
            yield file
        else:
            logger.debug(f'SearchFilter mismatch ID{file.id} [{yield_result}]')
            continue

class DefaultsTableWrapper:
    """
    This little class will wrap around the
    DEFAULTS table of TGBOX DB and will
    fetch all contents of it.

    You can await the ``change`` coroutine
    to change default values to your own.
    """
    def __init__(self, tgbox_db: TgboxDB):
        """
        Arguments:
            tgbox_db (``TgboxDB``):
                An initialized ``TgboxDB``.
        """
        self._tgbox_db = tgbox_db
        self._initialized = False

    def __repr__(self) -> str:
        return (f'{self.__class__.__name__}({repr(self._tgbox_db)})')

    def __str__(self) -> str:
        return (f'{self.__class__.__name__}({repr(self._tgbox_db)}) # {self._initialized=}')

    @property
    def initialized(self) -> bool:
        return self._initialized

    async def init(self) -> 'DefaultsTableWrapper':
        """Fetch the defaults and initialize"""
        logger.debug(
            '''Initializing DefaultsTableWrapper for '''
           f'''{self._tgbox_db._db_path} LocalBox'''
        )
        if self._tgbox_db.closed:
            await self._tgbox_db.init()

        defaults = await self._tgbox_db.DEFAULTS.select_once()
        for default, value in zip(TABLES['DEFAULTS'], defaults):
            setattr(self, default[0], value)

        self._initialized = True
        return self

    async def change(self, key: str, value) -> None:
        """
        This method can change the defaults values

        Arguments:
            key (``str``):
                Key to change, i.e METADATA_MAX.

            value:
                Key's new value.

        .. warning::
            We **don't** verify here that value
            type corresponds to real type of Key
            or that value doesn't overflow the
            allowed value maximum. Be sure to
            specify the correct Key values.

        Example:

        .. code-block:: python

            from asyncio import run as asyncio_run

            from tgbox.defaults import DEF_TGBOX_NAME
            from tgbox.api.db import TgboxDB
            from tgbox.api.utils import DefaultsTableWrapper

            async def main():
                # Make a DefaultsTableWrapper object
                tdb = await TgboxDB(DEF_TGBOX_NAME).init()
                dtw = await DefaultsTableWrapper(tdb).init()

                # Change METADATA_MAX to the max allowed size
                dtw.change('METADATA_MAX', 256**3-1)

                # Access DTW from the DecryptedLocalBox
                ... # Some code was omited here
                # Change the default download path
                dlb.defaults.change('DOWNLOAD_PATH', 'Downloads')

            asyncio_run(main())
        """
        getattr(self, key) # Vetrify that Key exist

        logger.info(f'Changing defaults | UPDATE DEFAULTS SET {key}={value}')
        await self._tgbox_db.DEFAULTS.execute((
            f'UPDATE DEFAULTS SET {key}=?', (value,)
        ))

@dataclass
class RemoteBoxDefaults:
    METADATA_MAX: int
    FILE_PATH_MAX: int
    DEF_UNK_FOLDER: Union[str, PathLike]
    DEF_NO_FOLDER: Union[str, PathLike]
    DOWNLOAD_PATH: Union[str, PathLike]


def _syncify_wrap_func(t, method_name):
    method = getattr(t, method_name)

    @wraps(method)
    def syncified(*args, **kwargs):
        coro = method(*args, **kwargs)
        try:
            loop = get_running_loop()
        except RuntimeError:
            loop = get_event_loop_policy().get_event_loop()

        if loop.is_running():
            return coro
        else:
            return loop.run_until_complete(coro)

    # Save an accessible reference to the original method
    setattr(syncified, '__tb.sync', method)
    setattr(t, method_name, syncified)

def _syncify_wrap_agen(t, method_name):
    method = getattr(t, method_name)

    @wraps(method)
    def syncified(*args, **kwargs):
        coro = method(*args, **kwargs)
        try:
            loop = get_running_loop()
        except RuntimeError:
            loop = get_event_loop_policy().get_event_loop()
        try:
            while True:
                if loop.is_running():
                    yield anext(coro)
                else:
                    yield loop.run_until_complete(anext(coro))
        except StopAsyncIteration:
            return

    # Save an accessible reference to the original method
    setattr(syncified, '__tb.sync', method)
    setattr(t, method_name, syncified)

def syncify(*types):
    """
    Converts all the methods in the given types (class definitions)
    into synchronous, which return either the coroutine or the result
    based on whether ``asyncio's`` event loop is running.
    """
    do_not_sync = ('search_generator',)

    for t in types:
        for name in dir(t):
            if name in do_not_sync:
                continue

            if not name.startswith('_') or name == '__call__':
                if isasyncgenfunction(getattr(t, name)):
                    _syncify_wrap_agen(t, name)

                elif iscoroutinefunction(getattr(t, name)):
                    _syncify_wrap_func(t, name)


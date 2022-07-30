"""Module with all API functions and classes."""
try:
    from regex import search as re_search
except ImportError:
    from re import search as re_search

from filetype import guess as filetype_guess
from asyncio import iscoroutinefunction

from telethon import TelegramClient
from telethon.sessions import StringSession

from telethon.tl.custom.file import File
from telethon.tl.functions.auth import ResendCodeRequest
from telethon.tl.functions.messages import EditChatAboutRequest

from telethon.errors import (
    SessionPasswordNeededError, 
    ChatAdminRequiredError, 
    AuthKeyUnregisteredError
)
from telethon.tl.functions.channels import (
    CreateChannelRequest, EditPhotoRequest,
    GetFullChannelRequest, DeleteChannelRequest
)
from telethon.tl.types import (
    Channel, Message, Photo, 
    PeerChannel, Document
)
from telethon import events
from telethon.tl.types.auth import SentCode

from .crypto import get_rnd_bytes
from .crypto import AESwState as AES

from .keys import (
    make_filekey, make_requestkey,
    EncryptedMainkey, make_mainkey,
    make_sharekey, MainKey, RequestKey, 
    ShareKey, ImportKey, FileKey, BaseKey
)
from .constants import (
    VERSION, VERBYTE, BOX_IMAGE_PATH, DEF_TGBOX_NAME, REMOTEBOX_PREFIX,
    FILE_NAME_MAX, FOLDERNAME_MAX, COMMENT_MAX, DEF_UNK_FOLDER,
    PREVIEW_MAX, DURATION_MAX, DEF_NO_FOLDER, NAVBYTES_SIZE,
    DOWNLOAD_PATH, FILESIZE_MAX, PREFIX
)
from .fastelethon import upload_file, download_file
from .db import TgboxDB

from .errors import (
    NotEnoughRights, NotATgboxFile,
    InUseException, BrokenDatabase, 
    RemoteBoxInaccessible, LimitExceeded,
    IncorrectKey, NotInitializedError,
    AlreadyImported, RemoteFileNotFound,
    DurationImpossible, SessionUnregistered,
    NotImported, AESError, PreviewImpossible
)
from .tools import (
    make_folder_id, get_media_duration, float_to_bytes, 
    int_to_bytes, bytes_to_int, RemoteBoxFileMetadata, 
    make_media_preview, SearchFilter, OpenPretender, 
    bytes_to_float, prbg, anext, pad_request_size
)
from typing import (
    BinaryIO, Union, NoReturn, Callable,
    AsyncGenerator, List, Optional
)
from sqlite3 import IntegrityError
from dataclasses import dataclass
from os.path import getsize
from pathlib import Path

from os import PathLike
from io import BytesIO
from time import time

from base64 import (
    urlsafe_b64encode, 
    urlsafe_b64decode 
)
__all__ = [
    'make_remote_box', 
    'get_remote_box', 
    'make_local_box', 
    'get_local_box', 
    'TelegramAccount', 
    'EncryptedRemoteBox',
    'DecryptedRemoteBox',
    'EncryptedRemoteBoxFile', 
    'DecryptedRemoteBoxFile', 
    'EncryptedLocalBox', 
    'DecryptedLocalBox', 
    'LocalBoxFolder', 
    'EncryptedLocalBoxFile', 
    'DecryptedLocalBoxFile', 
    'FutureFile'
]
TelegramClient.__version__ = VERSION

async def _search_func(
        sf: SearchFilter, 
        ta: Optional['TelegramAccount'] = None,
        mainkey: Optional[MainKey] = None,
        it_messages: Optional[AsyncGenerator] = None,
        lb: Optional[Union['DecryptedLocalBox', 'EncryptedLocalBox']] = None) -> AsyncGenerator:
    """
    Function used to search for files in dlb and rb. It's
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
        
        if isinstance(file, (EncryptedRemoteBoxFile, DecryptedRemoteBoxFile)):
            file_size = file.file_size
        elif isinstance(file, (EncryptedLocalBoxFile, DecryptedLocalBoxFile)):
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
                    if not indx: # O is Include
                        yield_result[indx] = False
                        break

                elif bool(file.exported) == bool(filter['exported']): 
                    if indx: # 1 is Exclude
                        yield_result[indx] = False
                        break
            
            if filter['min_time']:
                if file.upload_time < filter['min_time'][-1]:
                    if not indx:
                        yield_result[indx] = False
                        break

                elif file.upload_time >= filter['min_time'][-1]:
                    if indx:
                        yield_result[indx] = False
                        break

            if filter['max_time']:
                if file.upload_time > filter['max_time'][-1]: 
                    if not indx:
                        yield_result[indx] = False
                        break

                elif file.upload_time <= filter['max_time'][-1]: 
                    if indx:
                        yield_result[indx] = False
                        break

            if filter['min_size']:
                if file_size < filter['min_size'][-1]:
                    if not indx:
                        yield_result[indx] = False
                        break

                elif file_size >= filter['min_size'][-1]:
                    if indx:
                        yield_result[indx] = False
                        break

            if filter['max_size']:
                if file_size > filter['max_size'][-1]: 
                    if not indx:
                        yield_result[indx] = False
                        break

                elif file_size <= filter['max_size'][-1]: 
                    if indx:
                        yield_result[indx] = False
                        break

            if filter['min_id']:
                if file.id < filter['min_id'][-1]: 
                    if not indx:
                        yield_result[indx] = False
                        break

                elif file.id >= filter['min_id'][-1]: 
                    if indx:
                        yield_result[indx] = False
                        break

            if filter['max_id']:
                if file.id > filter['max_id'][-1]: 
                    if not indx:
                        yield_result[indx] = False
                        break

                elif file.id <= filter['max_id'][-1]: 
                    if indx:
                        yield_result[indx] = False
                        break
            
            for id in filter['id']:
                if file.id == id:
                    if indx:
                        yield_result[indx] = False
                    break
            else:
                if filter['id']:
                    if not indx:
                        yield_result[indx] = False
                        break

            for comment in filter['comment']:
                if file.comment and in_func(comment, file.comment):
                    if indx:
                        yield_result[indx] = False
                    break
            else:
                if filter['comment']:
                    if not indx:
                        yield_result[indx] = False
                        break

            for folder in filter['folder']:
                if in_func(folder, file.foldername):
                    if indx:
                        yield_result[indx] = False
                    break
            else:
                if filter['folder']:
                    if not indx:
                        yield_result[indx] = False
                        break

            for file_name in filter['file_name']:
                if in_func(file_name, file.file_name):
                    if indx:
                        yield_result[indx] = False
                    break
            else:
                if filter['file_name']:
                    if not indx:
                        yield_result[indx] = False
                        break

            for file_salt in filter['file_salt']:
                if in_func(file_salt, file.file_salt):
                    if indx:
                        yield_result[indx] = False
                    break
            else:
                if filter['file_salt']:
                    if not indx:
                        yield_result[indx] = False
                        break

            for verbyte in filter['verbyte']:
                if verbyte == file.verbyte:
                    if indx:
                        yield_result[indx] = False
                    break
            else:
                if filter['verbyte']:
                    if not indx:
                        yield_result[indx] = False
                        break
        
        if all(yield_result):
            yield file
        else:
            continue

async def make_remote_box(
        ta: 'TelegramAccount', 
        tgbox_db_name: str=DEF_TGBOX_NAME,
        tgbox_rb_prefix: str=REMOTEBOX_PREFIX,
        box_image_path: Union[PathLike, str] = BOX_IMAGE_PATH,
        box_salt: Optional[bytes] = None) -> 'EncryptedRemoteBox':
    """
    Function used for making ``RemoteBox``. 
    
    Arguments:
        ta (``TelegramAccount``):
            Account to make private Telegram channel.
            You must be signed in via ``sign_in()``.
        
        tgbox_db_name (``TgboxDB``, optional):
            Name of your Local and Remote boxes.
            ``constants.DEF_TGBOX_NAME`` by default.

        tgbox_rb_prefix (``str``, optional):
            Prefix of your RemoteBox.
            ``constants.REMOTEBOX_PREFIX`` by default.

        box_image_path (``PathLike``, optional):
            ``PathLike`` to image that will be used as
            ``Channel`` photo of your ``RemoteBox``.

            Can be setted to ``None`` if you don't
            want to set ``Channel`` photo.

        box_salt (``bytes``, optional):
            Random 32 bytes. Will be used in ``MainKey``
            creation. Default is ``crypto.get_rnd_bytes()``.
    """
    if box_salt and len(box_salt) != 32:
        raise ValueError('Box salt len != 32')

    tgbox_db = await TgboxDB.create(tgbox_db_name)
    if (await tgbox_db.BoxData.count_rows()): 
        raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

    channel_name = tgbox_rb_prefix + tgbox_db.name
    box_salt = urlsafe_b64encode(box_salt if box_salt else get_rnd_bytes())

    channel = (await ta.TelegramClient(
        CreateChannelRequest(channel_name,'',megagroup=False))).chats[0]
    
    if box_image_path:
        box_image = await ta.TelegramClient.upload_file(open(box_image_path,'rb'))
        await ta.TelegramClient(EditPhotoRequest(channel, box_image)) 

    await ta.TelegramClient(EditChatAboutRequest(channel, box_salt.decode()))
    return EncryptedRemoteBox(channel, ta)

async def get_remote_box(
        dlb: Optional['DecryptedLocalBox'] = None, 
        ta: Optional['TelegramAccount'] = None,
        entity: Optional[Union[int, str, PeerChannel]] = None)\
        -> Union['EncryptedRemoteBox', 'DecryptedRemoteBox']:
    """
    Returns ``EncryptedRemoteBox`` or 
    ``DecryptedRemoteBox`` if you specify ``dlb``.
    
    .. note::
        Must be specified at least ``dlb`` or ``ta`` with ``entity``. 
    
    Arguments:
        dlb (``DecryptedLocalBox``, optional):
            Should be specified if ``ta`` is ``None``.

        ta (``TelegramAccount``, optional):
            Should be specified if ``dlb`` is ``None``.
            ``entity`` should be specified with ``ta``.

            Note that ``ta`` must be already connected 
            with Telegram via ``await ta.connect()``.

        entity (``PeerChannel``, ``int``, ``str``, optional):
            Can be ``Channel`` ID, Username or ``PeerChannel``.
            Will be used if specified. Must be specified with ``ta``.
    """
    if ta:
        account = ta

    elif ta and not entity:
        raise ValueError('entity must be specified with ta')
    else:
        account = TelegramAccount(
            session=dlb._session,
            api_id=dlb._api_id,
            api_hash=dlb._api_hash
        )
        await account.connect()
    try:
        entity = entity if entity else PeerChannel(dlb._box_channel_id)
        channel_entity = await account.TelegramClient.get_entity(entity)
    except AuthKeyUnregisteredError:
        raise SessionUnregistered(
            '''Session was disconnected. Change it with '''
            '''DecryptedLocalBox.replace_session method.'''
        ) from None
    except ValueError:
        # ValueError: Could not find the input entity for PeerChannel
        raise RemoteBoxInaccessible(RemoteBoxInaccessible.__doc__) from None

    if not dlb:
        return EncryptedRemoteBox(channel_entity, account)
    else:
        return await EncryptedRemoteBox(
            channel_entity, account).decrypt(dlb=dlb)

async def make_local_box(
        erb: 'EncryptedRemoteBox', 
        ta: 'TelegramAccount', 
        basekey: BaseKey) -> 'DecryptedLocalBox':
    """
    Makes LocalBox

    Arguments:
        erb (``RemoteBox``):
            ``EncryptedRemoteBox``. You will
            recieve it after ``make_remote_box``.

        ta (``TelegramAccount``):
            ``TelegramAccount`` connected to Telegram.

        basekey (``BaseKey``):
            ``BaseKey`` that will be used 
            for ``MainKey`` creation. 
    """
    tgbox_db = await TgboxDB.create(await erb.get_box_name())
    if (await tgbox_db.BoxData.count_rows()): 
        raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

    box_salt = await erb.get_box_salt()
    mainkey = make_mainkey(basekey, box_salt)
    
    await tgbox_db.BoxData.insert(
        AES(mainkey).encrypt(int_to_bytes(0)),
        AES(mainkey).encrypt(int_to_bytes(erb._box_channel_id)),
        AES(mainkey).encrypt(int_to_bytes(int(time()))),
        box_salt,
        None, # We aren't cloned box, so Mainkey is empty
        AES(basekey).encrypt(ta.get_session().encode()),
        erb._ta._api_id, 
        bytes.fromhex(erb._ta._api_hash)
    )
    return await EncryptedLocalBox(tgbox_db).decrypt(basekey)

async def get_local_box(
        basekey: Optional[BaseKey] = None,
        tgbox_db_path: Optional[Union[PathLike, str]] = DEF_TGBOX_NAME,
        ) -> Union['EncryptedLocalBox', 'DecryptedLocalBox']:
    """
    Returns LocalBox.
    
    Arguments:
        basekey (``BaseKey``, optional):
            Returns ``DecryptedLocalBox`` if specified,
            ``EncryptedLocalBox`` otherwise (default).
            
        tgbox_db_path (``PathLike``, ``str``, optional):
            ``PathLike`` to your TgboxDB (LocalBox). Default
            is ``constants.DEF_TGBOX_NAME``.
    """
    if not isinstance(tgbox_db_path, PathLike):
        tgbox_db_path = Path(tgbox_db_path)

    if not tgbox_db_path.exists():
        raise FileNotFoundError(f'Can\'t open {tgbox_db_path.absolute()}') 
    else:
        tgbox_db = await TgboxDB(tgbox_db_path).init()

    if basekey:
        return await EncryptedLocalBox(tgbox_db).decrypt(basekey)
    else:
        return await EncryptedLocalBox(tgbox_db).init()

class TelegramAccount:
    """
    Wrapper around ``telethon.TelegramClient``
    
    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import TelegramAccount, make_remote_box
        from getpass import getpass # For hidden input
        
        PHONE_NUMBER = input('Your phone number: ')
        API_ID = 1234567 # Your own API_ID: my.telegram.org
        API_HASH = '00000000000000000000000000000000' # Your own API_HASH
        
        async def main():
            ta = TelegramAccount(
                phone_number = PHONE_NUMBER,
                api_id = API_ID, 
                api_hash = API_HASH
            )
            await ta.connect()
            await ta.send_code_request()

            await ta.sign_in(
                code = int(input('Code: ')),
                password = getpass('Pass: ')
            )
            erb = await make_remote_box(ta)

        asyncio_run(main())
    """
    def __init__(
            self, api_id: int, api_hash: str, 
            phone_number: Optional[str] = None, 
            session: Optional[Union[str, StringSession]] = None):
        """
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
                ``TelegramAccount.get_session()`` method.

            You should specify at least ``session`` or ``phone_number``.
        """
        if not session and not phone_number:
            raise ValueError(
                'You should specify at least ``session`` or ``phone_number``.'
            )
        self._api_id, self._api_hash = api_id, api_hash
        self._phone_number = phone_number
        
        self.TelegramClient = TelegramClient(
            StringSession(session), 
            self._api_id, self._api_hash
        )
    async def signed_in(self) -> bool:
        """Returns ``True`` if you logged in account"""
        return await self.TelegramClient.is_user_authorized()

    async def connect(self) -> 'TelegramAccount':
        """
        Connects to Telegram. Typically
        you will use this method if you have
        ``StringSession`` (``session`` specified).
        """
        await self.TelegramClient.connect()
        return self

    async def send_code_request(self, force_sms: bool=False) -> SentCode:
        """
        Sends the Telegram code needed to login to the given phone number.
        
        Arguments:
            force_sms (``bool``, optional):
                Whether to force sending as SMS.
        """
        return await self.TelegramClient.send_code_request(self._phone_number)

    async def sign_in(
            self, password: Optional[str] = None, 
            code: Optional[int] = None) -> None: 
        """
        Logs in to Telegram to an existing user account.
        You should only use this if you are not signed in yet.
        
        Arguments:
            password (``str``, optional):
                Your 2FA password. You can ignore 
                this if you don't enabled it yet.

            code (``int``, optional):
                The code that Telegram sent you after calling
                ``TelegramAccount.send_code_request()`` method.
        """
        if not await self.TelegramClient.is_user_authorized():
            try:
                await self.TelegramClient.sign_in(self._phone_number, code)
            except SessionPasswordNeededError:
                await self.TelegramClient.sign_in(password=password)

    async def log_out(self) -> bool:
        """
        Logs out from Telegram. Returns ``True`` 
        if the operation was successful.
        """
        return await self.TelegramClient.log_out()

    async def resend_code(self, phone_code_hash: str) -> SentCode:
        """
        Send log-in code again. This can be used to
        force Telegram send you SMS or Call to dictate code.
        
        Arguments:
            phone_code_hash (``str``):
                You can get this hash after calling
                ``TelegramAccount.send_code_request()``.

        Example:

        .. code-block:: python

            sent_code = await tg_account.send_code_request()
            sent_code = await tg_account.resend_code(sent_code.phone_code_hash)
        """
        return await self.TelegramClient(
            ResendCodeRequest(self._phone_number, phone_code_hash)
        )

    def get_session(self) -> str:
        """Returns ``StringSession`` as url safe base64 encoded ``str``"""
        return self.TelegramClient.session.save()
    
    async def tgboxes(self, yield_with: str=REMOTEBOX_PREFIX) -> AsyncGenerator:
        """
        Iterate over all Tgbox Channels in your account.
        It will return any channel with Tgbox prefix,
        ``.constants.REMOTEBOX_PREFIX`` by default, 
        you can override this with ``yield_with``.
        
        Arguments:
            yield_with (``str``):
                Any channel that have ``in`` title this
                string will be returned as ``RemoteBox``. 
        """
        async for d in self.TelegramClient.iter_dialogs():
            if yield_with in d.title and d.is_channel: 
                yield EncryptedRemoteBox(d, self)

class EncryptedRemoteBox:
    """
    *RemoteBox* is a remote cloud storage. You can
    upload files and download them later.

    Locally we only keep info about files (in *LocalBox*).
    You can fully restore your LocalBox from RemoteBox.
    
    .. note::
        In ``EncryptedRemoteBox`` you should specify ``MainKey``
        or ``DecryptedLocalBox``. Usually you want to use
        ``DecryptedRemoteBox``, not this class.
    
    Typical usage:

    .. code-block:: python
        
        from tgbox.api import (
            TelegramAccount, 
            make_local_box, 
            make_remote_box
        )
        from getpass import getpass
        from asyncio import run as asyncio_run
        
        PHONE_NUMBER = input('Your phone number: ')
        API_ID = 1234567 # Your own API_ID: my.telegram.org
        API_HASH = '00000000000000000000000000000000' # Your own API_HASH
        
        async def main():
            # Connecting and logging to Telegram
            ta = TelegramAccount(
                phone_number = PHONE_NUMBER,
                api_id = API_ID, 
                api_hash = API_HASH
            )
            await ta.connect()
            await ta.send_code_request()

            await ta.sign_in(
                code = int(input('Code: ')),
                password = getpass('Pass: ')
            )
            # Making base RemoteBox (EncryptedRemoteBox)
            erb = await make_remote_box(ta)

        asyncio_run(main())
    """
    def __init__(self, box_channel: Channel, ta: TelegramAccount):
        """
        Arguments:
            box_channel (``Channel``):
                Telegram channel that represents
                RemoteBox. By default have 
                ``.constants.REMOTEBOX_PREFIX`` in name
                and always encoded by urlsafe
                b64encode BoxSalt in description.

            ta (``TelegramAccount``):
                Telegram account that have ``box_channel``.
        """
        self._ta = ta
        self._enc_class = True

        self._box_channel = box_channel
        self._box_channel_id = box_channel.id

        self._box_salt = None 
        # We can't use await in __init__, so 
        # you should call get_box_salt for first.
        self._box_name = None
        # Similar to box_salt, call get_box_name.

    def __hash__(self) -> int:
        # Without 22 hash of int wil be equal to object's
        return hash((self._box_channel_id, 22))
        
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self._box_channel_id == other.box_channel_id
        ))
    @property
    def event(self) -> events.NewMessage:
        """
        Will return ``events.NewMessage`` for
        ``Channel`` of this *RemoteBox*.

        You can use it in Telethon's decorator,
        see *"Events Reference"* in Docs.
        """
        return events.NewMessage(chats=self.box_channel_id)

    @property
    def ta(self) -> TelegramAccount:
        """Returns ``TelegramAccount``"""
        return self._ta

    @property
    def is_enc_class(self) -> bool:
        """
        Returns ``True`` if you call it on
        ``EncryptedRemoteBox``.
        """
        return self._enc_class

    @property
    def box_channel(self) -> Channel:
        """Returns instance of ``Channel``"""
        return self._box_channel
    
    @property
    def box_channel_id(self) -> int:
        """Returns box channel id"""
        return self._box_channel_id
    
    async def get_box_salt(self) -> bytes:
        """
        Returns BoxSalt. Will be cached 
        after first method call.
        """
        if not self._box_salt:
            full_rq = await self._ta.TelegramClient(
                GetFullChannelRequest(channel=self._box_channel)
            )
            self._box_salt = urlsafe_b64decode(full_rq.full_chat.about)
            
        return self._box_salt
    
    async def get_box_name(self):
        """
        Returns name of ``RemoteBox``. 
        Will be cached after first method call.
        """
        if not self._box_name:
            entity = await self._ta.TelegramClient.get_entity(self._box_channel_id)
            self._box_name = entity.title.split(': ')[1]
        return self._box_name

    async def file_exists(self, id: int) -> bool:
        """
        Returns ``True`` if file with specified ``id``
        exists in RemoteBox. ``False`` otherwise.
        
        Arguments:
            id (``int``):
                File ID.
        """
        if await self.get_file(id, decrypt=False):
            return True
        else:
            return False
                
    async def get_file(
            self, 
            id: int, 
            key: Optional[Union[MainKey, FileKey, ImportKey]] = None,
            dlb: Optional['DecryptedLocalBox'] = None, 
            decrypt: bool=True,
            ignore_errors: bool=True,
            return_imported_as_erbf: bool=False,
            cache_preview: bool=True) -> Union[
                'EncryptedRemoteBoxFile', 
                'DecryptedRemoteBoxFile', None
            ]:
        """
        Returns file from the ``RemoteBox`` by the given ID.

        .. note::
            You may ignore ``key` and ``dlb`` if you call
            this method on ``DecryptedRemoteBox``.
        
        Arguments:
            id (``int``):
                File ID.
            
            key (``MainKey``, ``FileKey``, optional):
                Will be used to decrypt ``EncryptedRemoteBoxFile``.
            
            dlb (``DecryptedLocalBox``, optional):
                If file in your ``RemoteBox`` was imported from
                other ``RemoteBox`` then you can't decrypt it with
                specified mainkey, but if you already imported it
                to your LocalBox, then you can specify ``dlb`` and we 
                will use ``FILE_KEY`` from the Database.
                
                If ``decrypt`` specified but there is no ``key``,
                then we try to use mainkey from this ``dlb``.
                
                This kwarg works in tandem with ``ignore_errors`` 
                and ``return_imported_as_erbf`` if dlb doesn't have
                this file (tip: you need to import it with ``dlb.import_file``.

            decrypt (``bool``, optional):
                Returns ``DecryptedRemoteBoxFile`` if ``True`` (default),
                ``EncryptedRemoteBoxFile`` otherwise.

            ignore_errors (``bool``, optional):
                Ignore all errors related to decryption of the
                files in your ``RemoteBox``. If ``True``, (by default) 
                only returns file that was successfully decrypted. Can
                be useful if you have files that was imported from other
                ``RemoteBox`` and you don't want to specify ``dlb``.
            
            return_imported_as_erbf (``bool``, optional):
                If specified, returns file that method can't 
                decrypt (if imported) as ``EncryptedRemoteBoxFile``.

            cache_preview (``bool``, optional):
                Cache preview in returned by method
                RemoteBoxFiles or not. ``True`` by default.
        """     
        if hasattr(self, '_mainkey'):
            key = self._mainkey

        if hasattr(self, '_dlb'):
            dlb = self._dlb

        file_iter = self.files(
            key, dlb=dlb, decrypt=decrypt, 
            ids=id, cache_preview=cache_preview,
            return_imported_as_erbf=return_imported_as_erbf,
            ignore_errors=ignore_errors
        )
        try:
            return await anext(file_iter)
        # If there is no file by ``id``.
        except StopAsyncIteration: 
            return None

    async def files(
            self, key: Optional[Union[MainKey, FileKey]] = None, 
            dlb: Optional['DecryptedLocalBox'] = None, *, 
            ignore_errors: bool=True, 
            return_imported_as_erbf: bool=False, 
            limit: Optional[int] = None, 
            offset_id: int=0, max_id: int=0, 
            min_id: int=0, add_offset: int=0, 
            search: Optional[str] = None, 
            from_user: Optional[Union[str, int]] = None, 
            wait_time: Optional[float] = None, 
            ids: Optional[Union[int, List[int]]] = None, 
            reverse: bool=False, decrypt: bool=True,
            cache_preview: bool=True) -> AsyncGenerator[
                Union['EncryptedRemoteBoxFile', 
                      'DecryptedRemoteBoxFile'],
                None
            ]:
        """
        Yields every RemoteBoxFile from ``RemoteBox``.
        
        .. note::
            - The default order is from newest to oldest, but this\
            behaviour can be changed with the ``reverse`` parameter.
            - You can ignore ``key`` and ``dlb`` if you call\
            this method on ``DecryptedRemoteBox``.

        Arguments:
            key (``MainKey``, ``FileKey``, optional):
                Will be used to decrypt ``EncryptedRemoteBoxFile``.
            
            dlb (``DecryptedLocalBox``, optional):
                If file in your ``RemoteBox`` was imported from
                other ``RemoteBox`` then you can't decrypt it with
                specified mainkey, but if you already imported it
                to your LocalBox, then you can specify dlb and we 
                will use ``FILE_KEY`` from the Database.
                
                If ``decrypt`` specified but there is no ``key``,
                then we try to use mainkey from this dlb.
                
                This kwarg works in tandem with ``ignore_errors`` 
                and ``return_imported_as_erbf`` if dlb doesn't have
                this file (tip: you need to import it with ``dlb.import_file``.
            
            ignore_errors (``bool``, optional):
                Ignore all errors related to decryption of the
                files in your ``RemoteBox``. If ``True``, (by default) 
                only yields files that was successfully decrypted. Can
                be useful if you have files that was imported from other
                ``RemoteBox`` and you don't want to specify dlb.
            
            return_imported_as_erbf (``bool``, optional):
                If specified, yields files that generator can't 
                decrypt (imported) as ``EncryptedRemoteBoxFile``.
            
            limit (``int`` | ``None``, optional):
                Number of files to be retrieved. Due to limitations with
                the API retrieving more than 3000 messages will take longer
                than half a minute (or even more based on previous calls).
                The limit may also be ``None``, which would eventually return
                the whole history.
                    
            offset_id (``int``, optional):
                Offset message ID (only remote files *previous* to the given
                ID will be retrieved). Exclusive.
                
            max_id (``int``, optional):
                All the remote box files with a higher (newer) ID 
                or equal to this will be excluded.

            min_id (``int``, optional):
                All the remote box files with a lower (older) ID 
                or equal to this will be excluded.

            add_offset (``int``, optional):
                Additional message offset (all of the specified offsets +
                this offset = older files).

            search (``str``, optional):
                The string to be used as a search query.

            from_user (``str``, ``int``, optional):
                Only messages from this entity will be returned.

            wait_time (``int``, optional):
                Wait time (in seconds) between different
                ``GetHistoryRequest`` (Telethon). Use this parameter to avoid hitting
                the ````FloodWaitError```` as needed. If left to ``None``, it will
                default to 1 second only if the limit is higher than 3000.
                If the ````ids```` parameter is used, this time will default
                to 10 seconds only if the amount of IDs is higher than 300.

            ids (``int``, ``list``, optional):
                A single integer ID (or several IDs) for the box files that
                should be returned. This parameter takes precedence over
                the rest (which will be ignored if this is set). This can
                for instance be used to get the file with ID 123 from
                a box channel. Note that if the file-message doesn't exist, 
                ``None`` will appear in its place, so that zipping the list of IDs
                with the files can match one-to-one.
                
            reverse (``bool``, optional):
                If set to ``True``, the remote files will be returned in reverse
                order (from oldest to newest, instead of the default newest
                to oldest). This also means that the meaning of ``offset_id``
                parameter is reversed, although ``offset_id`` still be exclusive. 
                ``min_id`` becomes equivalent to ``offset_id`` instead of being ``max_id`` 
                as well since files are returned in ascending order.
            
            decrypt (``bool``, optional):
                Returns ``DecryptedRemoteBoxFile`` if ``True`` (default),
                ``EncryptedRemoteBoxFile`` otherwise.

            cache_preview (``bool``, optional):
                Cache preview in yielded by generator
                RemoteBoxFiles or not. ``True`` by default.
        """
        if hasattr(self, '_mainkey'):
            key = self._mainkey

        if hasattr(self, '_dlb'):
            dlb = self._dlb

        if decrypt and not any((key, dlb)):
            raise ValueError(
                'You need to specify key or dlb to be able to decrypt.'
            )
        key = key if (key or not dlb) else dlb._mainkey
        
        it_messages = self._ta.TelegramClient.iter_messages(
            self._box_channel, limit=limit, offset_id=offset_id,
            max_id=max_id, min_id=min_id, add_offset=add_offset,
            search=search, from_user=from_user, wait_time=wait_time,
            ids=ids, reverse=reverse
        )
        async for m in it_messages:
            if not m and ignore_errors:
                continue 

            elif not m and not ignore_errors:
                raise RemoteFileNotFound('One of requsted by you file doesn\'t exist')
            
            if m.document: 
                if not decrypt:
                    rbf = await EncryptedRemoteBoxFile(
                        m, self._ta, cache_preview=cache_preview).init()
                else:
                    try:
                        rbf = await EncryptedRemoteBoxFile(
                            m, self._ta, cache_preview=cache_preview).decrypt(key)
                    except Exception as e: # In case of imported file
                        if return_imported_as_erbf and not dlb:
                            rbf = await EncryptedRemoteBoxFile(
                                m, self._ta, cache_preview=cache_preview).init()

                        elif ignore_errors and not dlb:
                            continue

                        elif not ignore_errors and not dlb:
                            raise IncorrectKey(
                                'File is imported. Specify dlb?') from None
                        elif dlb:
                            # We try to fetch FileKey of imported file from DLB.
                            dlb_file = await dlb.get_file(m.id, cache_preview=False)
                            
                            # If we haven't imported this file to DLB
                            if not dlb_file:
                                if return_imported_as_erbf: 
                                    rbf = await EncryptedRemoteBoxFile(
                                        m, self._ta, cache_preview=cache_preview).init()
                                elif ignore_errors:
                                    continue
                                else:
                                    raise NotImported(
                                        """You don\'t have FileKey for this file. """
                                        """Set to True ``return_imported_as_erbf``?"""
                                    ) from None
                            else:
                                # We already imported file, so have FileKey
                                rbf = await EncryptedRemoteBoxFile(
                                    m, self._ta, cache_preview=cache_preview
                                ).decrypt(dlb_file._filekey)
                        else: 
                            raise e # Unknown Exception
                yield rbf

    async def search_file(
            self, 
            sf: SearchFilter, 
            mainkey: Optional[MainKey] = None,
            dlb: Optional['DecryptedLocalBox'] = None) ->\
            AsyncGenerator[Union['EncryptedRemoteBoxFile', 'DecryptedRemoteBoxFile'], None]:
        """
        This method used to search for files in your ``RemoteBox``.
        
        Arguments:
            sf (``SearchFilter``):
                ``SearchFilter`` with kwargs you like.

            mainkey (``MainKey``, optional):
                ``MainKey`` for this ``RemoteBox``. 

            dlb (``DecryptedLocalBox``, optional):
                LocalBox associated with this ``RemoteBox``. We
                will take ``MainKey`` from it.
        
        .. note::
            - If ``dlb`` and ``mainkey`` not specified, then method\
            will search on ``EncryptedRemoteBoxFile``. 
            - You may ignore this kwargs if you call this\
            method on ``DecryptedRemoteBox`` class.
        """
        if hasattr(self, '_mainkey'):
            mainkey = self._mainkey
        
        if hasattr(self, '_dlb'):
            dlb = self._dlb
        
        min_id = sf.in_filters['min_id'][-1] if sf.in_filters['min_id'] else 0
        max_id = sf.in_filters['max_id'][-1] if sf.in_filters['max_id'] else 0

        it_messages = self._ta.TelegramClient.iter_messages(
            self._box_channel, min_id=min_id, 
            max_id=max_id, reverse=True
        )
        sfunc = _search_func(
            sf, mainkey=mainkey, 
            it_messages=it_messages, 
            lb=dlb, ta=self._ta
        )
        async for file in sfunc:
            yield file

    async def push_file(
            self, ff: 'FutureFile', 
            progress_callback: Optional[Callable[[int, int], None]] = None,
            ) -> 'DecryptedRemoteBoxFile':
        """
        Uploads ``FutureFile`` to the ``RemoteBox``.
        
        Arguments:
            ff (``FutureFile``):
                File to upload. You should recieve
                it via ``DecryptedLocalBox.make_file``.

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters: 
                (downloaded_bytes, total). 
        """
        state = AES(ff.filekey, ff.file_iv)

        oe = OpenPretender(ff.file, state, ff.size)
        oe.concat_metadata(ff.metadata)
            
        ifile = await upload_file(
            self._ta.TelegramClient, oe,
            file_name=urlsafe_b64encode(ff.file_salt).decode(), 
            part_size_kb=512, file_size=ff.wm_size,
            progress_callback=progress_callback
        )
        try:
            file_message = await self._ta.TelegramClient.send_file(
                self._box_channel, file=ifile, 
                silent=True, force_document=True
            )
        except ChatAdminRequiredError:
            box_name = await self.get_box_name()
            raise NotEnoughRights(
                '''You don\'t have enough privileges to upload '''
               f'''files to remote {box_name}. Ask for it or '''
                '''use this box as read only.'''
            ) from None

        await ff.make_local(file_message.id, 
            int(file_message.date.timestamp())) 
        
        erbf = await EncryptedRemoteBoxFile(
            file_message, self._ta).init()
        return await erbf.decrypt(ff.dlb._mainkey)

    async def get_requestkey(self, basekey: BaseKey) -> RequestKey:
        """
        Returns ``RequestKey`` for this *RemoteBox*.
        You should use this method if you want
        to decrypt other's ``RemoteBox``.
        
        Arguments:
            basekey (``BaseKey``):
                To make a ``RequestKey`` for other's ``RemoteBox``
                you need to create new ``BaseKey`` for it. Later
                this key will be used for *Box* decryption.
        """
        box_salt = await self.get_box_salt()
        return make_requestkey(basekey, box_salt=box_salt)

    async def left(self) -> None:
        """
        With calling this method you will left
        *RemoteBox* ``Channel``.
        """
        await self._ta.TelegramClient.delete_dialog(
            self._box_channel)

    async def delete(self) -> None:
        """
        This method **WILL DELETE** *RemoteBox*.

        Use ``left()`` if you only want to left
        from ``Channel``, not delete it.

        You need to have rights for this.
        """
        try:
            await self._ta.TelegramClient(
                DeleteChannelRequest(self._box_channel)
            ) 
        except ChatAdminRequiredError:
            box_name = await self.get_box_name()
            raise NotEnoughRights(
                '''You don\'t have enough rights to delete '''
               f'''{box_name} RemoteBox.'''
            ) from None

    async def decrypt(
            self, *, key: Optional[Union[MainKey, ImportKey, BaseKey]] = None, 
            dlb: Optional['DecryptedLocalBox'] = None) -> 'DecryptedRemoteBox':
        
        if not key and not dlb:
            raise ValueError('Must be specified at least key or dlb')
        else:
            # We need BoxSalt if Key is BaseKey
            if isinstance(key, BaseKey):
                await self.get_box_salt()

            return DecryptedRemoteBox(self, key=key, dlb=dlb) 

class DecryptedRemoteBox(EncryptedRemoteBox):
    """
    *RemoteBox* is a remote cloud storage. You can
    upload files and download them later.

    Locally we only keep info about files (in *LocalBox*).
    You can fully restore your LocalBox from RemoteBox.

    This class represents decrypted RemoteBox, you can
    iterate over all decrypted files, clone and upload.
    
    .. code-block:: python

        from tgbox.api import get_local_box, get_remote_box
        from tgbox.keys import make_basekey, Phrase
    
        phrase = Phrase('very_bad_phrase')
        basekey = make_basekey(phrase)

        dlb = await dlb.get_local_box(basekey)
        drb = await get_remote_box(dlb)
        
        # Make a FutureFile
        ff = await dlb.make_file(open('cats.jpg','rb'))

        # Waiting file for upload, return DecryptedRemoteBoxFile
        drbf = await drb.push_file(ff)

        # Get some info
        print(drbf.file_name, drbf.size)

        # Remove file from RemoteBox
        await drbf.delete()
        
        # Check if file exists
        print(await drb.file_exists(drbf.id)
    """
    def __init__(
            self, erb: EncryptedRemoteBox, 
            key: Optional[Union[MainKey, ImportKey]] = None,
            dlb: Optional['DecryptedLocalBox'] = None):
        """
        Arguments:
            erb (``EncryptedRemoteBox``):
                ``EncryptedRemoteBox`` you want to decrypt.

            key (``MainKey``, ``ImportKey``, optional):
                Decryption ``Key``. Must be specified if ``dlb`` is ``None``.

            dlb (``DecryptedLocalBox``, optional):
                ``DecryptedLocalBox`` associated with this *RemoteBox*. 
                Must be specified if ``key`` is ``None``.
        """
        self._ta = erb._ta
        self._enc_class = False

        self._box_channel = erb._box_channel
        self._box_channel_id = erb._box_channel_id

        self._box_salt = erb._box_salt
        self._box_name = erb._box_name
        self._dlb = dlb

        if self._dlb:
            self._mainkey = self._dlb._mainkey
        else:
            if not key:
                raise ValueError('Must be specified at least key or dlb')
            
            if isinstance(key, (MainKey, ImportKey)):
                self._mainkey = MainKey(key.key)
            elif isinstance(key, BaseKey):
                self._mainkey = make_mainkey(key, self._box_salt)
            else:
                raise IncorrectKey('key is not Union[MainKey, ImportKey, BaseKey]')
    
    async def clone(
            self, basekey: BaseKey, 
            progress_callback: Optional[Callable[[int, int], None]] = None,
            box_path: Optional[Union[PathLike, str]] = None) -> 'DecryptedLocalBox':
        """
        This method makes ``LocalBox`` from ``RemoteBox`` and
        imports all RemoteBoxFiles to it.
        
        Arguments:
            basekey (``BaseKey``):
                ``BaseKey`` with which you will decrypt your
                cloned ``EncryptedLocalBox``. ``BaseKey`` encrypts
                Session and ``MainKey`` of original LocalBox.

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters: 
                (downloaded_bytes, total). 

            box_path (``PathLike``, ``str``, optional):
                Direct path with filename included. If
                not specified, then ``RemoteBox`` name used.
        """
        box_path = await self.get_box_name()\
            if not box_path else box_path

        tgbox_db = await TgboxDB.create(box_path)

        if (await tgbox_db.BoxData.count_rows()): 
            raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')
        
        last_file_id = 0
        async for erbf in self.files(decrypt=False, return_imported_as_erbf=True):
            last_file_id = erbf.id; break

        await tgbox_db.BoxData.insert(
            AES(self._mainkey).encrypt(int_to_bytes(last_file_id)),
            AES(self._mainkey).encrypt(int_to_bytes(self._box_channel_id)),
            AES(self._mainkey).encrypt(int_to_bytes(int(time()))),
            await self.get_box_salt(),
            AES(basekey).encrypt(self._mainkey.key),
            AES(basekey).encrypt(self._ta.get_session().encode()),
            self._ta._api_id,
            bytes.fromhex(self._ta._api_hash)
        )
        dlb = await EncryptedLocalBox(tgbox_db).decrypt(basekey)

        async for drbf in self.files(key=self._mainkey, decrypt=True, reverse=True):
            if progress_callback:
                if iscoroutinefunction(progress_callback):
                    await progress_callback(drbf.id, last_file_id)
                else:
                    progress_callback(drbf.id, last_file_id)

            await dlb.import_file(drbf, foldername=drbf.foldername)
        
        return dlb
        
    async def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this Box.
        You should use this method if you want
        to share your ``RemoteBox`` with other people.

        Arguments:
            reqkey (``RequestKey``, optional):
                User's ``RequestKey``. If isn't specified
                returns ``ShareKey`` of this box without
                encryption, so anyone with this key can
                decrypt **ALL** files in your ``RemoteBox``.
        """
        box_salt = await self.get_box_salt()
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, 
                mainkey=self._mainkey, 
                box_salt=box_salt
            )
        else:
            return make_sharekey(mainkey=self._mainkey)

class EncryptedRemoteBoxFile:
    """
    Class that represents encrypted remote
    file. Without decryption you can only
    retrieve basic information, like Prefix,
    Verbyte, BoxSalt, FileSalt & Enc Navbytes.

    More information you can get from docs.
    Typically you don't need to import this class.

    Retrieving:

    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_remote_box, get_local_box
        
        async def main():
            dlb = await get_local_box(basekey)
            drb = await get_remote_box(dlb)
            
            erbf = await drb.get_file(
                id = await dlb.get_last_file_id(), 
                decrypt = False
            )
            print(erbf.file_salt)
            print(erbf.prefix)

        asyncio_run(main())
    """
    def __init__(
            self, sended_file: Message, 
            ta: TelegramAccount, 
            cache_preview: bool=True):
        """
        Arguments:
            sended_file (``Message``):
                A ``Telethon``'s message object. This
                message should contain ``File``.

            ta (``TelegramAccount``):
                Your Telegram account.

            cache_preview (``bool``, optional):
                Cache preview in class or not. ``True`` by default. 
                This kwarg will be used later in ``DecryptedRemoteBoxFile``
        """
        self._initialized = False
        self._enc_class = True

        self._message = sended_file
        self._id = sended_file.id
        self._file = sended_file.file
        
        if not self._file:
            raise NotATgboxFile('Specified message doesn\'t have a document')

        self._sender = sended_file.post_author
        
        self._ta = ta
        self._cache_preview = cache_preview
        
        self._upload_time = int(self._message.date.timestamp()) 
        self._box_channel_id = sended_file.peer_id.channel_id
        self._file_size = self._file.size
        self._file_file_name = self._file.name

        self._size, self._file_name = None, None
        self._file_iv, self._file_salt = None, None
        self._comment, self._foldername = None, None
        self._duration, self._version_byte = None, None

        self._preview, self._box_salt = None, None
        self._prefix, self._navbytes = None, None

        if self._message.fwd_from:
            self._exported = True            
        else:
            self._exported = False
    
    def __hash__(self) -> int:
        if not self.initialized:
            raise NotInitializedError(
                'Must be initialized before hashing'
            )
        if self._enc_class:
            return hash((self._id, self._file_file_name))
        else:
            return hash((self._id, self._file_name))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def is_enc_class(self) -> bool:
        """
        Returns ``True`` if you call it on
        ``EncryptedRemoteBoxFile``.
        """
        return self._enc_class

    @property
    def initialized(self) -> bool:
        """Returns ``True`` if class was initialized."""
        return self._initialized
    
    @property
    def sender(self) -> Union[str, None]:
        """
        Returns post author if sign
        messages is enabled in 
        ``Channel``, ``None`` otherwise
        """
        return self._sender

    @property 
    def exported(self) -> bool:
        """
        Returns ``True`` if file was exported
        from other RemoteBox. ``False`` otherwise.
        """
        return self._exported
    
    @property
    def version_byte(self) -> Union[bytes, None]:
        """Returns Verbyte or ``None`` if not initialized"""
        return self._version_byte
    
    @property
    def box_salt(self) -> Union[bytes, None]:
        """Returns BoxSalt or ``None`` if not initialized"""
        return self._box_salt

    @property
    def upload_time(self) -> Union[int, None]:
        """Returns upload time or ``None`` if not initialized"""
        return self._upload_time

    @property
    def file_salt(self) -> Union[bytes, None]:
        """Returns FileSalt or ``None`` if not initialized"""
        return self._file_salt
    
    @property
    def id(self) -> int:
        """Returns message id."""
        return self._id
     
    @property
    def file(self) -> File:
        """Returns Telethon's ``File`` object."""
        return self._file
    
    @property
    def file_size(self) -> int:
        """Returns size of the ``File`` from ``Message`` object."""
        return self._file_size

    @property
    def file_name(self) -> Union[bytes, None]:
        """
        Returns file name from ``DecryptedRemoteBoxFile``
        and always ``None`` from ``EncryptedRemoteBoxFile``.
        """
        return self._file_name

    @property
    def file_file_name(self) -> bytes:
        """Returns *remote file* name."""
        return self._file_file_name

    @property
    def box_channel_id(self) -> int:
        """Returns ID of the Box Channel."""
        return self._box_channel_id

    @property
    def prefix(self) -> Union[bytes, None]:
        """Returns file prefix or ``None`` if not initialized"""
        return self._file_name
    
    def __raise_initialized(self) -> NoReturn:
        if not self.initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

    def disable_cache_preview(self) -> None:
        """
        Sets ``self._cache_preview`` to ``False``
        and removes cached preview from memory.
        """
        self._cache_preview = False
        self._preview = None
    
    def enable_cache_preview(self) -> None:
        """
        Sets ``self._cache_preview`` to ``True``.
        Preview will be cached after first
        ``object.get_preview()`` call.
        """
        self._cache_preview = True
    
    async def init(self, verify_prefix: bool=True) -> 'EncryptedRemoteBoxFile':
        """
        Downloads and parses Metadata constant header.

        Arguments:
            verify_prefix (``bool``, optional):
                If ``True``, will check that file has a
                ``tgbox.constants.PREFIX`` in metadata, and if 
                not, will raise a ``NotATgboxFile`` exception.
        """
        async for fixed_metadata in self._ta.TelegramClient.iter_download(
            self._message.document, offset=0, request_size=103):
                self._prefix = bytes(fixed_metadata[:6])
                if self._prefix != PREFIX:
                    raise NotATgboxFile(
                        f'''Invalid prefix! Expected {PREFIX}, '''
                        f'''got {self._prefix}'''
                    )
                self._version_byte = bytes(fixed_metadata[6:7])
                self._box_salt = bytes(fixed_metadata[7:39])
                self._file_salt = bytes(fixed_metadata[39:71])
                self._navbytes = bytes(fixed_metadata[71:])
                break
        self._initialized = True
        return self

    async def delete(self) -> None: 
        """
        TOTALLY removes file from RemoteBox. You and all
        participants of the ``EncryptedRemoteBox`` will
        lose access to it FOREVER. This action can't be
        undone. You need to have rights for this action.
        
        .. note::
            If you want to delete file only from 
            your LocalBox then you can use the
            same ``delete()`` method on your LocalBoxFile.
        """
        rm_result = await self._ta.TelegramClient.delete_messages(
            self._box_channel_id, [self._id]
        )
        if not rm_result[0].pts_count:
            raise NotEnoughRights(
                '''You don\'t have enough rights to delete '''
                '''file from this RemoteBox.'''
            ) from None
    
    def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        """
        Returns ``RequestKey`` for this file. You should
        use this method if you want to decrypt other's
        ``EncryptedRemoteBoxFile``.
        
        Arguments:
            mainkey (``MainKey``):
                To make a ``RequestKey`` for other's *RemoteBoxFile*
                you need to have your *Box*. Take key from your 
                ``DecryptedLocalBox`` and specify it here.
        """
        self.__raise_initialized()
        return make_requestkey(mainkey, file_salt=self._file_salt)
    
    async def decrypt(
            self, key: Union[MainKey, FileKey, ImportKey, BaseKey])\
            -> 'DecryptedRemoteBoxFile':
        """
        Returns ``DecryptedRemoteBoxFile``.
        
        Arguments:
            key (``MainKey``, ``FileKey``, ``ImportKey``, ``BaseKey``):
                Decryption key. All, except ``FileKey`` will be
                used to make ``FileKey`` for this file.
        """
        if not self.initialized:
            await self.init()
        return await DecryptedRemoteBoxFile(self, key).init()

class DecryptedRemoteBoxFile(EncryptedRemoteBoxFile):
    """
    This class represents decrypted remote file.
    You can retrieve all metadata info from properties.

    Typical usage:

    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box, get_remote_box
        from tgbox.keys import Phrase, make_basekey
        
        async def main():
            basekey = make_basekey(Phrase('very_bad_phrase'))

            dlb = await get_local_box(basekey)
            drb = await get_remote_box(dlb)

            drbf = await drb.get_file(
                id = await dlb.get_last_file_id(), 
                dlb = dlb
            )
            print(drbf.foldername)

            # Download file preview
            with open(f'preview_{drbf.file_name}','wb') as f:
                f.write((await drbf.get_preview()).read())

            # Download file, return BinaryIO
            file = await drbf.download()

        asyncio_run(main())
    """
    def __init__(
            self, erbf: EncryptedRemoteBoxFile, 
            key: Union[MainKey, FileKey, ImportKey]):
        """
        Arguments:
            erbf (``EncryptedRemoteBoxFile``):
                Instance of ``EncryptedRemoteBoxFile`` to decrypt.

            key (``MainKey``, ``FileKey``, ``ImportKey``):
                Decryption key. 
        """
        if not erbf.initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

        self._key = key
        self._erbf = erbf
        
        self._initialized = False
        self._enc_class = False

        self._message = erbf._message
        self._id = erbf._id
        self._file = erbf._file
        self._sender = erbf._sender
        
        self._ta = erbf._ta
        self._cache_preview = erbf._cache_preview
        
        self._box_channel_id = erbf._box_channel_id
        self._file_size = erbf._file_size
        
        self._upload_time, self._size = erbf._upload_time, None
        self._file_iv, self._file_salt = None, erbf._file_salt
        self._comment, self._foldername = None, None
        self._duration, self._version_byte = None, erbf._version_byte

        self._preview, self._exported = None, erbf._exported
        self._prefix, self._navbytes = erbf._prefix, None
        self._box_salt, self._file_name = erbf._box_salt, None
        self._preview_pos, self._file_pos = None, None
        self._file_file_name = erbf._file_file_name

        if isinstance(key, (FileKey, ImportKey)):
            self._filekey = FileKey(key.key)
            self._mainkey = None
        elif isinstance(key, BaseKey):
            self._mainkey = make_mainkey(key, self._box_salt)
            self._filekey = make_filekey(self._mainkey, self._file_salt)
        else:
            self._mainkey = self._key
            self._filekey = make_filekey(self._key, self._file_salt)
            
    @property
    def size(self) -> Union[int, None]:
        """Returns file size or ``None`` if not initialized."""
        return self._size
    
    @property
    def duration(self) -> Union[float, None]:
        """Returns duration or ``None`` if not initialized."""
        return self._duration
    
    @property
    def file_iv(self) -> Union[bytes, None]:
        """Returns file IV or ``None`` if not initialized."""
        return self._file_iv
    
    @property
    def comment(self) -> Union[bytes, None]:
        """Returns file comment or ``None`` if not initialized."""
        return self._comment
    
    @property
    def foldername(self) -> Union[bytes, None]:
        """Returns folder or ``None`` if not initialized."""
        return self._foldername

    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

    async def init(self) -> 'DecryptedRemoteBoxFile':
        """
        This method will download, decrypt and parse all
        Metadata, along with preview if ``cache_preview`` is
        enabled. Max request per file is ~1064639 bytes. Usually
        it not exceed 20KB per one file.
        """
        dec_navbytes = AES(self._filekey).decrypt(self._erbf._navbytes)

        # This should be True when LocalBox hasn't Key for imported file.
        if len(dec_navbytes) == NAVBYTES_SIZE-16:
            raise AESError('Navbytes wasn\'t decrypted correctly. Incorrect key?')
        
        filedata_len = bytes_to_int(dec_navbytes[:3],signed=False)
        preview_len = bytes_to_int(dec_navbytes[3:],signed=False)
        request_size = pad_request_size(filedata_len)

        async for filedata in self._ta.TelegramClient.iter_download(
            self._message.document, offset=103, request_size=request_size):
                
                filedata = filedata[:filedata_len]
                dec_filedata = AES(self._filekey).decrypt(filedata)

                self._size = bytes_to_int(dec_filedata[:4],signed=False)
                self._duration = bytes_to_float(dec_filedata[4:8])
                folder_len = bytes_to_int(dec_filedata[8:10],signed=False)
                
                self._foldername = dec_filedata[10:10+folder_len] 

                if self._mainkey:
                    self._foldername = AES(self._mainkey).decrypt(self._foldername)
                else:
                    self._foldername = DEF_NO_FOLDER

                pos = 10 + folder_len
                comment_len = bytes_to_int(dec_filedata[pos:pos+1],signed=False)
                self._comment = dec_filedata[pos+1:pos+1+comment_len]
                
                pos += 2 + comment_len
                filename_len = bytes_to_int(dec_filedata[pos:pos+1],signed=False)
                self._file_name = dec_filedata[pos+1:pos+filename_len+1]
                break
        
        if preview_len:
            self._preview_pos = (103+filedata_len, preview_len)
        else:
            self._preview_pos = ()

        self._file_pos = 103 + filedata_len + preview_len + 16
        self._initialized = True
        
        async for file_iv in self._ta.TelegramClient.iter_download(
            self._message.document, offset=self._file_pos-16, request_size=16):
                self._file_iv = bytes(file_iv); break

        if preview_len and self._cache_preview:
            await self.get_preview()

        elif preview_len and not self._cache_preview:
            self._preview = None
        else:
            self._preview = b''
        
        return self

    async def get_preview(self) -> bytes:
        """Returns and caches file preview after first call."""

        self.__raise_initialized()
        if self._preview is not None:
            return self._preview

        if isinstance(self._preview_pos, tuple) and not self._preview_pos:
            preview = b''
        else:
            request_size = pad_request_size(self._preview_pos[1])
            offset = self._preview_pos[0]

            async for preview in self._ta.TelegramClient.iter_download(
                self._message.document, offset=offset, request_size=request_size):
                    preview = preview[:self._preview_pos[1]]
                    preview = AES(self._filekey).decrypt(preview)
                    break
        
        if self._cache_preview:
            self._preview = preview
        return preview

    async def download( 
            self, *, outfile: Union[str, BinaryIO, Path] = DOWNLOAD_PATH, 
            hide_folder: bool=False, hide_name: bool=False,
            decrypt: bool=True, request_size: int=524288,
            progress_callback: Optional[Callable[[int, int], None]] = None) -> BinaryIO:
        """
        Downloads and saves remote box file to the ``outfile``.
        
        Arguments:
            oufile (``str``, ``BinaryIO``, ``PathLike``, optional):
                Path-like or File-like object to which file 
                will be downloaded. ``.constants.DOWNLOAD_PATH`` by default.
                
                If ``outfile`` has ``.write()`` method then we will use it.
            
            hide_folder (``bool``, optional):
                Saves to folder which this file belongs to if False,
                (default) otherwise to ``outfile/{constants.DEF_UNK_FOLDER}``.
                
                Doesn't create any folders if ``isinstance(outfile, BinaryIO)``.
            
            hide_name (``bool``, optional):
                Saves file with encrypted name if True, with
                decrypted if False (default).
                
                Doesn't create any folders if ``isinstance(outfile, BinaryIO)``.
            
            decrypt (``bool``, optional):
                Decrypts file if True (default).
            
            request_size (``int``, optional):
                How many bytes will be requested to Telegram when more 
                data is required. By default, as many bytes as possible 
                are requested. If you would like to request 
                data in smaller sizes, adjust this parameter.

                Note that values outside the valid range will be clamped, 
                and the final value will also be a multiple 
                of the minimum allowed size.

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters: 
                (downloaded_bytes, total). 
        """
        self.__raise_initialized()
        
        if decrypt:
            aws = AES(self._filekey, self._file_iv)
        
        if isinstance(outfile, (str, PathLike)):
            Path(outfile).mkdir(exist_ok=True)
            outfile = Path(outfile) if not isinstance(outfile, PathLike) else outfile

            folder = DEF_UNK_FOLDER if hide_folder else self._foldername
            folder = DEF_NO_FOLDER if not folder else folder
            name = prbg(16).hex().encode() if hide_name else self._file_name
            
            outfile = Path(
                outfile, folder.decode().lstrip('/'), 
                name.decode().lstrip('/')
            )
            outfile.parent.mkdir(exist_ok=True, parents=True)
            outfile = open(outfile,'wb')
            
        elif isinstance(outfile, BinaryIO) or hasattr(outfile, 'write'):
            pass # We already can write 
        else:
            raise TypeError('outfile not Union[BinaryIO, str, PathLike].')
        
        iter_down = download_file(
            client = self._ta.TelegramClient,
            location = self._message.document,
            request_size = request_size,
        )
        buffered, offset, total = b'', self._file_pos, 0
        async for chunk in iter_down:
            if buffered:
                buffered += chunk
                chunk = buffered[:request_size]
                buffered = buffered[request_size:]
            else:
                buffered += chunk[offset:]
                offset = None; continue
            
            chunk = aws.decrypt(chunk, unpad=False) if decrypt else chunk
            outfile.write(chunk)

            if progress_callback:
                total += len(chunk)
                if iscoroutinefunction(progress_callback):
                    await progress_callback(total, self._file_size)
                else:
                    progress_callback(total, self._file_size)

        if buffered:
            outfile.write(aws.decrypt(buffered, unpad=True) if decrypt else chunk)

            if progress_callback:
                if iscoroutinefunction(progress_callback):
                    await progress_callback(
                        self._file_size, self._file_size)
                else:
                    progress_callback(
                        self._file_size, self._file_size)
        return outfile
    
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this file. You should
        use this method if you want to share this
        file with other people.
        
        Arguments:
            reqkey (``RequestKey``, optional):
                Other's ``RequestKey``. If isn't specified
                returns ``ImportKey`` of this file without
                encryption, so **ANYONE** with this key 
                can decrypt this remote file.
        """
        self.__raise_initialized()

        if reqkey:
            return make_sharekey(
                requestkey=reqkey, filekey=self._filekey, 
                file_salt=self._file_salt
            )
        else:
            return make_sharekey(filekey=self._filekey)
        
class EncryptedLocalBox:
    """
    This class represents an encrypted local box. On more
    low-level that's a wrapper around ``TgboxDB``. Usually
    you will never meet this class in your typical code, 
    but you may want to extract some encrypted data.

    Usage:

    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import EncryptedLocalBox
        from tgbox.db import TgboxDB
        
        async def main():
            # Make or open TgboxDB
            tdb = await TgboxDB.create('TGBOX')
            # Initialize EncryptedLocalBox
            elb = await EncryptedLocalBox(tdb).init()
            
            # Retrieve encrypted session
            print(elb.session)
        
        asyncio_run(main())

    You can acces it from ``DecryptedLocalBox``:

    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box
        from tgbox.keys import make_basekey, Phrase
        
        async def main():
            basekey = make_basekey(Phrase('very_bad_phrase'))
            dlb = await get_local_box(basekey)

            # Retrieve encrypted session
            print(dlb._elb.session)

        asyncio_run(main())
    """
    def __init__(self, tgbox_db: TgboxDB):
        """
        Arguments:
            tgbox_db (``TgboxDB``):
                Initialized Tgbox Database.
        """
        self._tgbox_db = tgbox_db
        
        self._api_id = None
        self._api_hash = None

        self._mainkey = None
        self._box_salt = None
        self._session = None

        self._box_channel_id = None
        self._box_cr_time = None

        self._initialized = False
        self._enc_class = True
            
    def __hash__(self) -> int:
        if not self._initialized:
            raise NotInitializedError(
                'Must be initialized before hashing'
            )
        # Session will be different in Enc or Dec classes.
        return hash((self._box_salt, self._session))
        
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().')
    
    @property
    def api_id(self) -> Union[int, None]:
        """Returns API_ID."""
        return self._api_id

    @property
    def api_hash(self) -> Union[str, None]:
        """Returns API_HASH."""
        return self._api_hash

    @property
    def tgbox_db(self) -> TgboxDB:
        """Returns ``TgboxDB``."""
        return self._tgbox_db
   
    @property
    def is_enc_class(self) -> bool:
        """Returns ``True`` if we\'re in EncryptedLocalBox"""
        return self._enc_class

    @property
    def initialized(self) -> bool:
        """Returns ``True`` if you called ``.init()``"""
        return self._initialized

    @property 
    def box_salt(self) -> Union[bytes, None]:
        """Returns BoxSalt or ``None`` if not initialized"""
        return self._box_salt
    
    @property
    def session(self) -> Union[bytes, str, None]:
        """
        Returns encrypted session from 
        ``EncryptedLocalBox`` and decrypted 
        from ``DecryptedLocalBox``.
        """
        return self._session
    
    @property
    def box_channel_id(self) -> Union[bytes, int, None]:
        """
        Returns encrypted channel ID from 
        ``EncryptedLocalBox`` and decrypted 
        from ``DecryptedLocalBox``.
        """
        return self._box_channel_id
    
    @property
    def box_cr_time(self) -> Union[bytes, int, None]:
        """
        Returns encrypted box creation time from 
        ``EncryptedLocalBox`` and decrypted 
        from ``DecryptedLocalBox``.
        """
        return self._box_cr_time
    
    async def get_last_file_id(self) -> Union[bytes, int, None]:
        """
        Returns encrypted last file ID from 
        ``EncryptedLocalBox`` and decrypted 
        from ``DecryptedLocalBox``.
        """
        lfi = await self._tgbox_db.BoxData.select_once(
            sql_tuple = ('SELECT LAST_FILE_ID FROM BOX_DATA', ())
        )
        if not self._enc_class:
            lfi = AES(self._mainkey).decrypt(lfi[0])

        return lfi[0] if self._enc_class else lfi
    
    async def init(self) -> 'EncryptedLocalBox':
        """Will fetch and parse data from Database."""

        if not await self._tgbox_db.BoxData.count_rows():
            raise NotInitializedError('Table is empty.') 
        else:
            box_data = await self._tgbox_db.BoxData.select_once()
            last_file_id, self._box_channel_id = box_data[:2]
            self._box_cr_time, self._box_salt, self._mainkey = box_data[2:5]
            self._session, self._initialized = box_data[5], True
            self._api_id, self._api_hash = box_data[6], box_data[7].hex()
            
            if self._mainkey:
                self._mainkey = EncryptedMainkey(self._mainkey)

        return self

    async def get_file(self, id: int, cache_preview: bool=True)\
            -> Union['DecryptedLocalBoxFile', 'EncryptedLocalBoxFile', None]:
        """
        Returns ``EncryptedLocalBoxFile`` from ``EncryptedLocalBox``
        or ``DecryptedLocalBoxFile`` from ``DecryptedLocalBox`` if
        file exists. ``None`` otherwise.
        
        Arguments:
            id (``int``):
                File ID.

            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        try:
            self.__raise_initialized()
            elbfi = EncryptedLocalBoxFile(
                id, self._tgbox_db, 
                cache_preview=cache_preview
            )
            if self._mainkey and not isinstance(self._mainkey, EncryptedMainkey):
                return await elbfi.decrypt(self._mainkey)
            else:
                return await elbfi.init()
        except StopAsyncIteration: # No file by ``id``.
            return None
    
    async def files(
            self, cache_preview: bool=True,
            min_id: Optional[int] = None,
            max_id: Optional[int] = None)\
            -> Union[
                'DecryptedLocalBoxFile', 
                'EncryptedLocalBoxFile', None
               ]:
        """
        Yields every local file as ``EncryptedLocalBoxFile`` if you
        call it on ``EncryptedLocalBox`` and ``DecryptedLocalBoxFile``
        if on ``DecryptedLocalBox``. Works via ``self.get_file``
        
        Arguments:
            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        min_id = f'ID > {min_id}' if min_id else ''
        max_id = f'ID < {max_id}' if max_id else ''
        
        min_id = min_id + ' AND' if all((min_id,max_id)) else min_id
        where = 'WHERE' if any((min_id, max_id)) else ''

        sql_query = f'SELECT ID FROM FILES {where} {min_id} {max_id}'
        cursor = await self._tgbox_db.Files.execute((sql_query ,()))

        async for file_id in cursor:
            yield await self.get_file(file_id[0], cache_preview=cache_preview)

    def get_requestkey(self, basekey: BaseKey) -> RequestKey:
        """
        Returns ``RequestKey`` for this *LocalBox*.
        You should use this method if you want
        to decrypt other's ``RemoteBox``.
        
        Arguments:
            basekey (``BaseKey``):
                To make a ``RequestKey`` for other's ``RemoteBox``
                you need to create new ``BaseKey`` for it. Later
                this key will be used for *Box* decryption.
        """
        self.__raise_initialized()
        return make_requestkey(basekey, box_salt=self._box_salt)
    
    def delete(self) -> None:
        """
        This method **WILL DELETE** your *LocalBox* 
        database. It doesn't affect *RemoteBox*,
        so you can make new *LocalBox* from the
        *Remote* version if you have *MainKey*.

        Will raise ``FileNotFoundError`` if
        something goes wrong (i.e DB was moved).
        """
        self._tgbox_db.db_path.unlink()

    async def decrypt(self, basekey: BaseKey) -> 'DecryptedLocalBox':
        if not self.initialized:
            await self.init()
        return DecryptedLocalBox(self, basekey)

class DecryptedLocalBox(EncryptedLocalBox):
    """
    Class that represents decrypted local box. On
    more low-level it's wrapper around ``TgboxDB`` that
    decrypts and parses every row. You don't need to
    work with ``EncryptedLocalBox`` to write any data
    to the ``TgboxDB``. Every commit will be encrypted here.

    Typical usage:

    .. code-block: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box
        from tgbox.keys import make_basekey, Phrase
        
        async def main():
            basekey = make_basekey(Phrase('very_bad_phrase'))
            dlb = await get_local_box(basekey)
            
            # Iterating over all files
            async for dlbfi in dlb.files():
                print(file.id, file.file_name, file.size)

        asyncio_run(main())
    """
    def __init__(self, elb: EncryptedLocalBox, basekey: BaseKey):
        """
        Arguments:
            elb (``EncryptedLocalBox``):
                Local box you want to decrypt.

            basekey (``BaseKey``):
                Your ``BaseKey``. 
        """
        if not elb.initialized:
            raise NotInitializedError('Parent class isn\'t initialized.')

        self._elb = elb
        self._tgbox_db = elb._tgbox_db
        self._initialized = True 
        self._enc_class = False
        
        if isinstance(basekey, BaseKey):
            if isinstance(elb._mainkey, EncryptedMainkey):
                mainkey = AES(basekey).decrypt(elb._mainkey.key)
                self._mainkey = MainKey(mainkey)
            else:
                self._mainkey = make_mainkey(basekey, self._elb._box_salt)
            try:
                # We encrypt Session with Basekey to prevent stealing 
                # Session information by people who also have mainkey 
                # of the same box. So there is decryption with basekey.
                self._session = AES(basekey).decrypt(elb._session).decode()
            except UnicodeDecodeError:
                raise IncorrectKey('Can\'t decrypt Session. Invalid Basekey?') 
        else:
            raise IncorrectKey('basekey is not BaseKey')

        self._box_channel_id = bytes_to_int(
            AES(self._mainkey).decrypt(elb._box_channel_id)
        )
        self._box_cr_time = bytes_to_int(
            AES(self._mainkey).decrypt(elb._box_cr_time)
        )
        self._box_salt = elb._box_salt
        self._api_id = elb._api_id
        self._api_hash = elb._api_hash

    @staticmethod
    def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBox`` """
            """and cannot be used on ``DecryptedLocalBox``."""
        )
    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBox`` """
            """and cannot be used on ``DecryptedLocalBox``."""
        )
    async def folders(self) -> AsyncGenerator['LocalBoxFolder', None]:
        """Iterate over all folders in LocalBox."""

        folders_list = await self._tgbox_db.Folders.execute(
            (f'SELECT * FROM FOLDERS',)
        )
        async for folder in folders_list:
            yield LocalBoxFolder(
                self._tgbox_db, self._mainkey,
                enc_foldername = folder[0],
                folder_iv = folder[1],
                folder_id = folder[2]
            )
    async def sync(
            self, drb: DecryptedRemoteBox, 
            start_from: int=0,
            progress_callback: Optional[Callable[[int, int], None]] = None,
            include_preview: bool=True):
        """
        This method will synchronize your LocalBox
        with RemoteBox. All files that not in RemoteBox
        but in Local will be **removed**, all that 
        in Remote but not in LocalBox will be imported.

        drb (``DecryptedRemoteBox``):
            *RemoteBox* associated with this LocalBox.

        start_from (``int``, optional):
            Will check files that > start_from [ID].

        include_preview (``bool``, optional):
            Will download and save file preview
            to the LocalBox if ``True`` (by default). 
        """
        async def _get_file(n=start_from):
            iter_over = drb.files(
                min_id=n, reverse=True, 
                cache_preview=False,
                return_imported_as_erbf=True
            )
            async for drbf in iter_over:
                return drbf
        
        def difference(sql_tuple_ids: tuple) -> bool:
            """
            This local func will sort out useless SQL
            querys, like DELETE FROM FILES WHERE ID > 5 AND ID < 5
            """
            if sql_tuple_ids[0] == sql_tuple_ids[1] \
                or sql_tuple_ids[0]+1 == sql_tuple_ids[1]:
                    return False
            else:
                return True

        async for drbf in drb.files(cache_preview=False):
            last_drbf_id = drbf.id; break
        
        rbfiles = []

        while True:
            current = 0
            
            if None in rbfiles:
                break
            
            if not rbfiles:
                rbfiles.append(await _get_file())
                
                if rbfiles[0] is None:
                    # RemoteBox doesn't have any files
                    await self._tgbox_db.Files.execute(
                        sql_tuple=('DELETE FROM FILES', ()))
                    break

                rbfiles.append(await _get_file(rbfiles[0].id))
                last_id = rbfiles[0].id

                sql_tuple = (
                    'DELETE FROM FILES WHERE ID < ?', 
                    (last_id,)
                )
                await self._tgbox_db.Files.execute(
                    sql_tuple=sql_tuple
                )
            else:
                rbfiles.append(await _get_file(rbfiles[1].id))
                if None in rbfiles: break
            
                rbfiles.append(await _get_file(rbfiles[2].id-1))
                if None in rbfiles: break
                rbfiles.pop(0); rbfiles.pop(1)
            
            if progress_callback:
                if iscoroutinefunction(progress_callback):
                    await progress_callback(last_id, last_drbf_id)
                else:
                    progress_callback(last_id, last_drbf_id)
            
            while True:
                if current == 2 or not rbfiles[current]:
                    break
                try:
                    lbfi_id = await self._tgbox_db.Files.select_once(
                        sql_tuple = (
                            'SELECT ID FROM FILES WHERE ID=?', 
                            (rbfiles[current].id,)
                        )
                    )
                except StopAsyncIteration:
                    lbfi_id = None
                
                if lbfi_id or type(rbfiles[current]) is EncryptedRemoteBoxFile:
                    current += 1
                else:
                    if include_preview:
                        rbfiles[current]._cache_preview = True
                        await rbfiles[current].get_preview()
                    
                    await self.import_file(rbfiles[current])
                    
                    if current == 0:
                        rbfiles[0] = rbfiles[1]

                    if None in rbfiles: 
                        break

                    rbfiles[1] = await _get_file(rbfiles[0].id)
                    
                    if rbfiles[0] and not rbfiles[1]:
                        if current == 0:
                            try:
                                await self.import_file(rbfiles[current])
                            except AlreadyImported:
                                pass # Last file may be already in Box, so skip

                        rbfiles[1] = rbfiles[0]
                        break
                    else:
                        last_id = rbfiles[1].id
            
            sql_tuple = (
                'DELETE FROM FILES WHERE ID > ? AND ID < ?',
                (last_id, rbfiles[0].id)
            )
            if difference(sql_tuple[1]):
                await self._tgbox_db.Files.execute(sql_tuple=sql_tuple)
            
            last_id = rbfiles[1].id if rbfiles[1] else None
            
            if last_id:
                sql_tuple = (
                    'DELETE FROM FILES WHERE ID > ? AND ID < ?',
                    (rbfiles[0].id, rbfiles[1].id)
                )
                if difference(sql_tuple[1]):
                    await self._tgbox_db.Files.execute(sql_tuple=sql_tuple)
            else:
                sql_tuple = (
                    'DELETE FROM FILES WHERE ID = ?',
                    (rbfiles[0].id,)
                )
                await self._tgbox_db.Files.execute(sql_tuple=sql_tuple)
                break

    async def replace_session(
            self, basekey: BaseKey, ta: TelegramAccount) -> None:
        """
        This method will replace LocalBox session to
        session of specified ``TelegramAccount``.

        Arguments:
            basekey (``BaseKey``):
                ``BaseKey`` of this *LocalBox*.

            ta (``TelegramAccount``):
                ``TelegramAccount`` from which we
                will extract new session. 
        """
        try:
            AES(basekey).decrypt(self._elb._session).decode()
        except UnicodeDecodeError:
            raise IncorrectKey(
                'BaseKey doesn\'t match with BaseKey of LocalBox') from None
        else:
            self._session = ta.get_session()

            session = AES(basekey).encrypt(self._session.encode())
            self._elb._session = session

            sql_tuple = ('UPDATE BOX_DATA SET SESSION = ?',(session,))
            await self._tgbox_db.BoxData.execute(sql_tuple) 

    async def search_file(
            self, sf: SearchFilter) -> AsyncGenerator[
                'DecryptedLocalBoxFile', None
            ]:
        """
        This method used to search for files in your ``DecryptedLocalBox``.
        
        Arguments:
            sf (``SearchFilter``):
                ``SearchFilter`` with kwargs you like.
        """
        async for file in _search_func(sf, lb=self, mainkey=self._mainkey):
            yield file
        
    async def make_file( 
            self, file: Union[BinaryIO, bytes, Document, Photo],
            file_size: Optional[int] = None,
            foldername: bytes = DEF_NO_FOLDER,
            file_name: Optional[bytes] = None,
            comment: bytes = b'',
            make_preview: bool = True) -> 'FutureFile':
        """
        Prepares your file for ``RemoteBox.push_file``

        Arguments:
            file (``BinaryIO``, ``BytesIO``):
                ``file`` data to add to the LocalBox. In most
                cases it's just opened file. If you want to upload
                something else, then you need to implement class
                that have ``read`` & ``name`` methods.
                
                The method needs to know size of the ``file``, so
                it will try to ask system what size of file on path
                ``file.name``. If it's impossible, then method tries to
                seek file to EOF, if file isn't seekable, then we try to
                get size by ``len()`` (as ``__len__`` dunder). If all fails,
                method tries to get ``file.read())`` (with load to RAM).
                
                File name length must be <= ``constants.FILE_NAME_MAX``;
                Filesize must be <= ``constants.FILESIZE_MAX``;
                If file has no ``name`` then it will be ``prbg(6).hex()``.
            
            file_size (``int``, optional):
                Bytelength of ``file``. You can specify
                it if you already know file size.

            foldername (``bytes``, optional):
                Folder to add this file to.
                Must be <= ``constants.FOLDERNAME_MAX``.

            file_name (``bytes``, optional):
                Your custom file name. This will
                be used instead of ``file.name``.
               
                Max length is ``constants.FILESIZE_MAX``.

                Note that ``file.name`` will be used
                for determining file size. Look above 
                at ``file`` arg docstring for more details.
            
            comment (``bytes``, optional):
                File comment. Must be <= ``constants.COMMENT_MAX``.
            
            make_preview (``bool``, optional):
                Will try to add file preview to 
                the Metadata if ``True`` (default).
        """
        if len(comment) > COMMENT_MAX:
            raise LimitExceeded(f'Comment length must be <= {COMMENT_MAX} bytes.')
                
        file_salt, file_iv = get_rnd_bytes(), get_rnd_bytes(16)
        filekey = make_filekey(self._mainkey, file_salt)
        
        if isinstance(file, (Document, Photo)):
            class TelegramVirtualFile:
                def __init__(self, doc_pic, session):
                    # Will be used for if conditions
                    self.telegram_vf = None

                    self.downloader = None
                    self.doc_pic = doc_pic

                    self.ta = TelegramAccount(
                        session=session,
                        api_id=self._api_id,
                        api_hash=self._api_hash
                    )
                    self.ta = self.ta.connect()
                    self._client_initialized = False
                    
                    file = File(doc_pic)
                    self.name = file.name
                    self.size = file.size

                    self.duration = file.duration\
                        if file.duration else 0
                
                async def get_preview(self, quality: int=1) -> bytes:
                    if not self._client_initialized:
                        self.ta = await self.ta
                        self._client_initialized = True
                
                    if hasattr(self.doc_pic,'sizes')\
                        and not self.doc_pic.sizes:
                            return b''

                    if hasattr(self.doc_pic,'thumbs')\
                        and not self.doc_pic.thumbs:
                            return b''

                    return await self.ta.TelegramClient.download_media(
                        message = self.doc_pic, 
                        thumb = quality, file = bytes
                    )
                async def read(self, size: int) -> bytes:
                    if not self._client_initialized:
                        self.ta = await self.ta
                        self._client_initialized = True

                    if not self.downloader:
                        self.downloader = download_file(
                            self.ta.TelegramClient, self.doc_pic
                        )
                    chunk = await anext(self.downloader)
                    return chunk
                    
            file = TelegramVirtualFile(file, self._session)
            make_preview = False # We will call get_preview
        
        if file_name:
            file_path = '' 
        elif hasattr(file,'name') and file.name:
            file_path = Path(file.name)
            file_name = file_path.name
        else:
            file_name, file_path = prbg(8).hex(), ''
        
        if not isinstance(file_name, bytes):
            file_name = file_name.encode()

        if len(file_name) > FILE_NAME_MAX: 
            raise LimitExceeded(f'File name must be <= {FILE_NAME_MAX} bytes.')
        
        if not file_size:
            if hasattr(file, 'telegram_vf'):
                file_size = file.size 
            else:
                try:
                    file_size = getsize(file.name)
                except (FileNotFoundError, AttributeError):
                    if isinstance(file, bytes):
                        file_size = len(file)
                        file = BytesIO(file)

                    elif hasattr(file, '__len__'):
                        file_size = len(file)

                    elif hasattr(file,'seek') and file.seekable():
                        file.seek(0,2)
                        file_size = file.tell()
                        file.seek(0,0)
                    else:
                        rb, file_size = file.read(), len(rb)
                        file = BytesIO(rb); del(rb)
                    
            if file_size > FILESIZE_MAX:
                raise LimitExceeded(f'File size limit is {FILESIZE_MAX} bytes.')
        
        if make_preview and file_path:
            file_type = filetype_guess(file_path)
            file_type = file_type if not file_type\
                else file_type.mime.split('/')[0]
        else:
            file_type = None

        preview, duration = b'', 0
        
        if hasattr(file, 'telegram_vf'):
            preview = await file.get_preview()
            duration = file.duration
        
        if file_type in ('audio','video','image'):
            try:
                preview = (await make_media_preview(file.name)).read()
            except PreviewImpossible:
                pass

            if file_type in ('audio','video'):
                try:
                    duration = await get_media_duration(file.name) 
                except DurationImpossible:
                    pass 
        
        # Although we store preview size in 3 bytes, the max
        # preview size is 1MB-16b (PREVIEW_MAX), not 16MiB.
        preview = b'' if len(preview) > PREVIEW_MAX else preview
        # Duration can't be bigger than DURATION_MAX. As per
        # v1.0 it's ~68.1 years. More than enough.
        duration = 0 if duration > DURATION_MAX else duration

        return FutureFile(
            dlb = self, 
            file_name = file_name,
            foldername = foldername, 
            file = file,
            filekey = filekey, 
            comment = comment,
            size = file_size, 
            preview = preview, 
            duration = duration,
            file_salt = file_salt, 
            file_iv = file_iv, 
            verbyte = VERBYTE,
            imported = False
        )
    async def import_file( 
            self, drbf: DecryptedRemoteBoxFile,
            foldername: Optional[bytes] = None)\
            -> 'DecryptedLocalBoxFile':
        """
        Imports file to your ``DecryptedLocalBox``

        Arguments:
            drbf (``DecryptedRemoteBoxFile``):
                Remote file you want to import.

            foldername (``bytes``, optional):
                File's folder. Will be used
                ``drbf._foldername`` if ``None``.
        """
        ff = FutureFile(
            self, file_name=drbf._file_name,
            foldername=(foldername if foldername else drbf._foldername), 
            file=BytesIO(), 
            filekey=drbf._filekey,
            comment=drbf._comment, 
            size=drbf._size,
            preview=(await drbf.get_preview()),
            duration=drbf._duration,
            file_salt=drbf._file_salt,
            file_iv=drbf._file_iv,
            verbyte=drbf._version_byte,
            imported=True
        )
        return await ff.make_local(drbf._id, drbf._upload_time)
    
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this Box. You should use
        this method if you want to share your LocalBox
        with other people.
        
        Arguments:
            reqkey (``RequestKey``, optional):
                Other's ``RequestKey``. If isn't specified
                returns ``ImportKey`` of this box without
                encryption, so anyone with this key can
                decrypt **ALL** files in your Boxes.
        """
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, 
                mainkey=self._mainkey, 
                box_salt=self._box_salt
            )
        else:
            return make_sharekey(mainkey=self._mainkey)
    
class LocalBoxFolder:
    """
    Class that represents abstract Tgbox folder. You
    can iterate over all files in this folder.

    Typical usage:

    .. code-block:: python

        ...
        # Iterate over all folders, recieve ``LocalBoxFolder``
        async for folder in dlb.folders():
            print('@ FOLDER:', folder.dec_foldername)

            # Iterate over all files
            async for dlbfi in folder.files():
                print(dlbfi.id, dlbfi.file_name, dlbfi.comment)
    """
    def __init__(
            self, tgbox_db: TgboxDB, 
            mainkey: MainKey, 
            enc_foldername: bytes,
            folder_iv: bytes,
            folder_id: bytes):
        """
        To make a ``LocalBoxFolder`` you need to
        fetch one row from ``FOLDERS`` table.
        
        Arguments:
            tgbox_db (``TgboxDB``):
                Tgbox Database.

            mainkey (``MainKey``):
                Decryption key associated
                with ``tgbox_db``.

            enc_foldername (``bytes``):
                Encrypted ``FOLDER`` from
                TgboxDB ``FOLDERS`` table.

            folder_iv (``bytes``):
                ``FOLDER_IV`` from
                TgboxDB ``FOLDERS`` table.

            folder_id (``bytes``):
                ``FOLDER_ID`` from
                TgboxDB ``FOLDERS`` table.
        """
        self._tgbox_db = tgbox_db
        
        self._enc_foldername = enc_foldername
        self._folder_iv = folder_iv
        self._folder_id = folder_id

        self._dec_foldername = AES(mainkey, self._folder_iv).decrypt(
            self._enc_foldername
        )
        self._mainkey = mainkey

    def __hash__(self) -> int:
        # Without 22 hash of bytes wil be equal to object's
        return hash((self._enc_foldername, 22))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def enc_foldername(self) -> bytes:
        """Returns encrypted foldername"""
        return self._enc_foldername
    
    @property
    def dec_foldername(self) -> bytes:
        """Returns decrypted foldername"""
        return self._dec_foldername

    async def files(self, cache_preview: bool=True) -> 'DecryptedLocalBoxFile':
        """
        Iterate over all files in this abstract folder.
        
        Arguments:
            cache_preview (``bool``, optional):
                Cache preview in class or not. 
                ``True`` by default.
        """
        files_list = await self._tgbox_db.Files.execute( 
            ('SELECT * FROM FILES WHERE FOLDER_ID = ?', (self._folder_id,))
        )
        async for file_row in files_list:
            yield await self.get_file(file_row[0], cache_preview=cache_preview)

    async def get_file(
            self, id: int, cache_preview: bool=True
            ) -> 'DecryptedLocalBoxFile':
        """
        Returns file by given ID.
        
        Arguments:
            id (``int``):
                File ID.

            cache_preview (``bool``, optional):
                Will save preview image (max ~1MB) in 
                ``EncryptedLocalBoxFile`` object if ``True`` (default).
        """
        return await EncryptedLocalBoxFile(
            id, self._tgbox_db, cache_preview=cache_preview
        ).decrypt(self._mainkey)

    async def delete(self) -> None: 
        """
        Will delete this folder with all files from your LocalBox.
        All files will stay in ``RemoteBox``, so you can restore
        all your folders by importing files.
        """
        await self._tgbox_db.Files.execute(
            ('DELETE FROM FILES WHERE FOLDER_ID=?',(self._folder_id,))
        )
        await self._tgbox_db.Folders.execute(
            ('DELETE FROM FOLDERS WHERE FOLDER_ID=?',(self._folder_id,))
        )

class EncryptedLocalBoxFile:
    """
    This class represents an encrypted local file. On
    more low-level that's a wrapper around row of
    ``FILES`` table in Tgbox Database. Usually you
    will not use this in your code.

    You can access it via ``DecryptedLocalBoxFile``:

    .. code-block:: python

        ...
        dlbfi = await dlb.get_file(
            await dlb.get_last_file_id()
        )
        print(dlbfi._elbfi.foldername) # Encrypted
    """
    def __init__(
            self, id: int, tgbox_db: TgboxDB, 
            cache_preview: bool=True) -> None:
        """
        Arguments:
            id (``int``):
                File ID.

            tgbox_db (``TgboxDB``):
                Tgbox Database.

            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        self._tgbox_db = tgbox_db
        self._cache_preview = cache_preview
        
        self._enc_class = True
        self._initialized = False
        
        self._foldername, self._preview = None, None
        self._folder_iv, self._folder = None, None
        self._file_name, self._folder_id = None, None        
        self._comment, self._size = None, None
        self._duration, self._id = None, id
        self._upload_time, self._file_salt = None, None
        self._file_iv, self._filekey = None, None
        self._version_byte, self._file_path = None, None
        self._exported, self._file = None, None
        
    def __hash__(self) -> int:
        return hash(self._id)
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def is_enc_class(self) -> bool:
        """
        Returns ``True`` if you call it 
        on ``EncryptedLocalBoxFile``
        """
        return self._enc_class
   
    @property
    def initialized(self) -> bool:
        """
        Returns ``True`` if you 
        already called ``.init()``
        """
        return self._initialized
    
    @property
    def file(self) -> Union[BinaryIO, None]:
        """
        Returns opened file as ``BinaryIO`` if it was 
        downloaded, otherwise ``None``. File returns 
        "as is", and it will be not decrypted if 
        you downloaded it in encrypted state.
        
        Will always return ``None`` from 
        ``EncryptedLocalBoxFile``, because ``FILE_PATH``
        is encrypted with filekey.
        """
        return self._file
    
    @property
    def exported(self) -> Union[bool, None]:
        """
        Returns ``True`` if file was 
        forwarded to your BoxChannel.
        """
        return self._exported
    
    @property
    def version_byte(self) -> Union[bytes, None]:
        """
        Returns Verbyte of this file. 
        Returns ``None`` if class wasn't initialized
        """
        return self._version_byte
    
    @property
    def file_path(self) -> Union[bytes, None]:
        """
        Returns encrypted ``file_path`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._file_path

    @property
    def file_name(self) -> Union[bytes, None]:
        """
        Returns encrypted ``file_name`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._file_name

    @property
    def foldername(self) -> Union[bytes, None]:
        """
        Returns encrypted ``foldername`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._foldername

    @property
    def size(self) -> Union[bytes, int, None]:
        """
        Returns encrypted ``size`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._size
    
    @property
    def duration(self) -> Union[bytes, float, None]:
        """
        Returns encrypted ``duration`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._duration
    
    @property
    def comment(self) -> Union[bytes, None]:
        """
        Returns encrypted ``comment`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._comment

    @property
    def id(self) -> Union[int, None]:
        """
        Returns file ID or ``None`` 
        if file wasn't initialized
        """
        return self._id
    
    @property
    def file_iv(self) -> Union[bytes, None]:
        """
        Returns file IV or ``None`` 
        if file wasn't initialized
        """
        return self._file_iv

    @property
    def upload_time(self) -> Union[bytes, int, None]:
        """
        Returns encrypted ``upload_time`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._upload_time

    @property
    def file_salt(self) -> Union[bytes, None]:
        """
        Returns FileSalt or ``None`` 
        if file wasn't initialized
        """
        return self._file_salt

    @property
    def preview(self) -> Union[bytes, None]:
        """
        Returns encrypted ``preview`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized and ``b''``
        if this file hasn't preview.
        """
        return self._preview
    
    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().') 
    
    async def init(self) -> 'EncryptedLocalBoxFile':
        """Will fetch and parse data from Database."""

        preview = '' if not self._cache_preview else ' PREVIEW,'

        sql_query = (
             """SELECT ID, FOLDER_ID, COMMENT, DURATION, FILE_IV, """
            f"""FILE_KEY, FILE_NAME, FILE_SALT,{preview} SIZE, """
             """UPLOAD_TIME, VERBYTE, FILE_PATH FROM FILES WHERE ID=?"""
        )
        sql_file_row = list(await self._tgbox_db.Files.select_once(
            sql_tuple = (sql_query, (self._id,))
        ))
        if not self._cache_preview:
            sql_file_row.insert(8, None)

        self._file_name, self._folder_id = sql_file_row[6], sql_file_row[1]
        
        self._comment, self._size = sql_file_row[2], sql_file_row[9]
        self._duration, self._id = sql_file_row[3], sql_file_row[0]
        self._upload_time, self._file_salt = sql_file_row[10], sql_file_row[7] 
        self._file_iv, self._filekey = sql_file_row[4], sql_file_row[5]
        self._version_byte, self._file_path = sql_file_row[11], sql_file_row[12]
        
        self._preview = sql_file_row[8] if sql_file_row[8] else b''
        try:
            cursor = await self._tgbox_db.Folders.execute(
                ('SELECT * FROM FOLDERS WHERE FOLDER_ID = ?',(self._folder_id,))
            )
            self._foldername, self._folder_iv, self._folder_id = (
                await cursor.fetchone()
            )
        except Exception as e:
            raise BrokenDatabase(f'Can\'t read your DB. {e}') from None

        self._exported = True if self._filekey else False
        self._initialized = True

        return self

    def disable_cache_preview(self) -> None:
        """
        Sets ``self._cache_preview`` to ``False``
        and removes cached preview from memory.
        """
        self._cache_preview = False
        self._preview = b''
    
    def enable_cache_preview(self) -> None:
        """
        Sets ``self._cache_preview`` to ``True``.
        Preview will be cached after first
        ``object.preview`` call.
        """
        self._cache_preview = True
    
    def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        """ 
        Returns ``RequestKey`` for this File. You
        should use this method if you want to decrypt
        other's ``EncryptedLocalBoxFile``.
        
        Arguments:
            mainkey (``MainKey``):
                To make a ``RequestKey`` for other's
                ``EncryptedLocalBoxFile`` you need to have
                your own Box. Take key from it and specify here.
        """
        self.__raise_initialized()
        return make_requestkey(mainkey, file_salt=self._file_salt)

    async def decrypt(self, key: Union[FileKey, MainKey]) -> 'DecryptedLocalBoxFile':
        """
        Returns decrypted by ``key`` ``EncryptedLocalBoxFile``
        
        Arguments:
            key (``FileKey``, ``MainKey``):
                Decryption key.
        """
        if not self.initialized:
            await self.init()
        return DecryptedLocalBoxFile(self, key)

    async def delete(self) -> None:
        """
        Will delete this file from your LocalBox. You can
        re-import it from ``RemoteBox`` with ``import_file``. 

        .. note::
            This will delete file only from your LocalBox.
            To completly remove your file use same 
            function on ``EncryptedRemoteBoxFile``.
        """
        # Getting file row for FOLDER_ID
        file_row = await self._tgbox_db.Files.select_once(
            sql_tuple=('SELECT * FROM FILES WHERE ID=?',(self._id,))
        )
        # Removing requested file
        await self._tgbox_db.Files.execute(
            ('DELETE FROM FILES WHERE ID=? LIMIT 1',(self._id,))
        )
        # Getting cursor for all files with same FOLDER_ID as removed file.
        cursor = await self._tgbox_db.Files.execute(
            ('SELECT ID FROM FILES WHERE FOLDER_ID=?',(file_row[1],))
        )
        # If there is no more files with same folder, then remove it.
        if not await cursor.fetchone():
            await self._tgbox_db.Files.execute(
                ('DELETE FROM FOLDERS WHERE FOLDER_ID=? LIMIT 1',(file_row[1],))
            )

class DecryptedLocalBoxFile(EncryptedLocalBoxFile):
    """
    This class represents an decrypted local file. 
    On more low-level that's a wrapper of ``FILES``
    table in Tgbox Database that decrypts row. 

    Typical usage:

    .. code-block:: python

        ...
        dlbfi = await dlb.get_file(
            await dlb.get_last_file_id()
        )
        print(dlbfi.foldername) # Decrypted
    """
    def __init__(
            self, elbfi: EncryptedLocalBoxFile, 
            key: Union[FileKey, ImportKey, MainKey],
            cache_preview: Optional[bool] = None):
        """
        Arguments:
            elbfi (``EncryptedLocalBoxFile``):
                Encrypted local box file that
                you want to decrypt.

            key (``FileKey``, ``ImportKey``, ``MainKey``):
                Decryption key.

            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        if not elbfi.initialized:
            raise NotInitializedError('You should init elbfi firstly')

        self._elbfi = elbfi
        self._key = key
        self._tgbox_db = elbfi._tgbox_db
        
        self._filekey = elbfi._filekey
        self._file_salt = elbfi._file_salt

        if cache_preview is None:
            self._cache_preview = elbfi._cache_preview
        else:
            self._cache_preview = cache_preview

        self._enc_class = False
        self._initialized = True 

        if isinstance(key, (FileKey, ImportKey)):
            self._filekey = FileKey(key.key)
        elif isinstance(key, MainKey) and self._filekey:
            self._filekey = FileKey(
                AES(self._key).decrypt(self._filekey)
            )
        else:
            self._filekey = make_filekey(self._key, self._file_salt)
        
        if isinstance(key, MainKey):
            self._mainkey = key
        else:
            self._mainkey = None

        self._folder = None

        self._folder_iv = elbfi._folder_iv
        self._file_iv, self._folder_id = elbfi._file_iv, elbfi._folder_id
        self._id, self._file_salt = elbfi._id, elbfi._file_salt
        self._version_byte = elbfi._version_byte
        self._exported = True if elbfi._filekey else False

        if elbfi._file_path: 
            self._file_path = AES(self._filekey).decrypt(
                elbfi._file_path).decode()
            try:
                self._file = open(self._file_path,'rb')
            except:
                self._file = None
        else:
            self._file_path, self._file = None, None

        self._file_name = AES(self._filekey).decrypt(elbfi._file_name)

        if self._mainkey:
            self._foldername = AES(self._mainkey, self._folder_iv).decrypt(
                elbfi._foldername)
        else:
            self._foldername = DEF_NO_FOLDER

        self._comment = AES(self._filekey).decrypt(elbfi._comment)
        self._size = bytes_to_int(AES(self._filekey).decrypt(elbfi._size))
        self._duration = bytes_to_float(AES(self._filekey).decrypt(elbfi._duration))
        self._upload_time = bytes_to_int(AES(self._filekey).decrypt(elbfi._upload_time))
        
        if not self._cache_preview:
            self._preview = None
        
        if elbfi._preview and self._cache_preview:
            self._preview = AES(self._filekey).decrypt(elbfi._preview)
        else:
            self._preview = b''
        
        self._download_path = DOWNLOAD_PATH 
    
    @staticmethod
    def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxFile`` """
            """and cannot be used on ``DecryptedLocalBoxFile``."""
        )
    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxFile`` """
            """and cannot be used on ``DecryptedLocalBoxFile``."""
        )
    @property
    def download_path(self) -> str:
        """Returns current download path"""
        return self._download_path

    async def get_preview(self) -> bytes: 
        """
        Returns file preview. If there is no preview 
        then returns ``b''``. If ``EncryptedLocalBoxFile``
        parent (``self._elbfi``) disabled ``cache_preview``, then
        every call of this method will open DB & decrypt PREVIEW.
        """
        if self._preview:
            return self._preview
        else:
            cursor = await self._tgbox_db.Files.execute(
                ('SELECT PREVIEW FROM FILES WHERE ID=?',(self._id,))
            )
            preview = (await cursor.fetchone())[0]
            preview = AES(self._filekey).decrypt(preview)
            
            if self._cache_preview:
                self._preview = preview
            return preview

    async def get_folder(self) -> LocalBoxFolder:
        """
        Returns ``LocalBoxFolder`` associated with
        this ``DecryptedLocalBoxFile``.
        """
        if not self._folder:
            self._folder = LocalBoxFolder(
                self._tgbox_db, 
                self._mainkey, 
                self._elbfi.foldername,
                self._folder_iv,
                self._folder_id
            )
        return self._folder
    
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this file. You should
        use this method if you want to share your
        ``DecryptedLocalBoxFile`` with other people.
        
        Arguments:
            reqkey (``RequestKey``, optional):
                Other's ``RequestKey``. If isn't specified
                returns ``ShareKey`` of this file without
                encryption, so anyone with this key can
                decrypt this local & remote box file.
        """
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, filekey=self._filekey, 
                file_salt=self._file_salt
            )
        else:
            return make_sharekey(filekey=self._filekey)

@dataclass
class FutureFile:
    """
    This dataclass stores data needed for upload 
    in future, by ``DecryptedRemoteBox.push_file``. 
    After pushing used for LocalBoxFile creation.

    Usually it's only for internal use.
    """
    dlb: DecryptedLocalBox
    file_name: bytes
    foldername: bytes
    file: BinaryIO
    filekey: FileKey
    comment: bytes
    size: int
    preview: bytes
    duration: float
    file_salt: bytes
    file_iv: bytes
    verbyte: bytes
    imported: bool

    @property
    def wm_size(self) -> int:
        """Returns file + metadata length."""
        return self.size + len(self.metadata)

    @property
    def metadata(self) -> RemoteBoxFileMetadata:
        """Returns Metadata compiled from class data."""
        if not hasattr(self, '_metadata'):
            enc_foldername = AES(self.dlb._mainkey).encrypt(self.foldername)

            self._metadata = RemoteBoxFileMetadata(
                file_name = self.file_name,
                enc_foldername = enc_foldername,
                filekey = self.filekey,
                comment = self.comment,
                size = self.size,
                preview = self.preview,
                duration = self.duration,
                file_salt = self.file_salt,
                box_salt = self.dlb._box_salt,
                file_iv = self.file_iv,
                verbyte = self.verbyte
            )
        return self._metadata

    async def make_local(self, id: int, upload_time: int) -> DecryptedLocalBoxFile:
        """
        Creates LocalBoxFile.
        
        Arguments:
            id (``int``):
                File ID, recieved after
                ``RemoteBox.push_file``.

            upload_time (``int``):
                UNIX time stamp after file
                was uploaded to ``RemoteBox``.
        """
        duration = float_to_bytes(self.duration)
        size = int_to_bytes(self.size)
        upload_time = int_to_bytes(upload_time)
        try:
            # Verify that there is no file with same ID
            maybe_file = await self.dlb._tgbox_db.Files.select_once(
                sql_tuple=('SELECT ID FROM FILES WHERE ID=?', (id,))
            )
        except StopAsyncIteration:
            pass
        else:
            raise AlreadyImported('There is already file with same ID') from None

        if self.imported:
            filekey = AES(self.dlb._mainkey).encrypt(self.filekey.key)
        else:
            filekey = None

        file_path = None
        if hasattr(self.file, 'name') and self.file.name:
            if Path(self.file.name).exists():
                file_path = AES(self.filekey).encrypt(self.file.name.encode())
        
        folder_id = make_folder_id(self.dlb._mainkey, self.foldername)

        # We're checking if there is already the same folder (1)
        cursor = await self.dlb._tgbox_db.Folders.execute(
            ('SELECT FOLDER_ID FROM FOLDERS WHERE FOLDER_ID = ?', (folder_id,))
        )
        # And if not, we're add it (2)
        if not await cursor.fetchone(): 
            # We're use MainKey for folder encryption 
            folder = AES(self.dlb._mainkey).encrypt(self.foldername)

            await self.dlb._tgbox_db.Folders.insert(
                folder[16:], folder[:16], folder_id)
        
        await self.dlb._tgbox_db.Files.insert(
            id, 
            folder_id,
            AES(self.filekey).encrypt(self.comment),
            AES(self.filekey).encrypt(duration),
            self.file_iv, 
            filekey,
            AES(self.filekey).encrypt(self.file_name),
            self.file_salt,
            AES(self.filekey).encrypt(self.preview),
            AES(self.filekey).encrypt(size),
            AES(self.filekey).encrypt(upload_time),
            self.verbyte,
            file_path
        )
        enc_id = AES(self.dlb._mainkey).encrypt(int_to_bytes(id))
        
        sql_tuple = ('UPDATE BOX_DATA SET LAST_FILE_ID = ?',(enc_id,))
        await self.dlb._tgbox_db.BoxData.execute(sql_tuple) 

        return await EncryptedLocalBoxFile(
            id, self.dlb._tgbox_db).decrypt(self.filekey)

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
    ChatAdminRequiredError, 
    MediaCaptionTooLongError,
    AuthKeyUnregisteredError,
    SessionPasswordNeededError,
    FilePartsInvalidError
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
from .defaults import (
    REMOTEBOX_PREFIX, DEF_NO_FOLDER, DOWNLOAD_PATH, 
    VERSION, VERBYTE, BOX_IMAGE_PATH, DEF_TGBOX_NAME, 
    PREFIX, METADATA_MAX, FILE_PATH_MAX, DEF_UNK_FOLDER
)
from .fastelethon import upload_file, download_file
from .db import TgboxDB

from .errors import (
    NoPlaceLeftForMetadata,
    NotEnoughRights, NotATgboxFile, 
    InUseException, BrokenDatabase, 
    IncorrectKey, NotInitializedError,
    AlreadyImported, RemoteFileNotFound,
    RemoteBoxInaccessible, LimitExceeded,
    DurationImpossible, SessionUnregistered,
    NotImported, AESError, PreviewImpossible
)
from .tools import (
    int_to_bytes, bytes_to_int, SearchFilter, OpenPretender,
    pad_request_size, PackedAttributes, ppart_id_generator,
    get_media_duration, prbg, anext, make_media_preview,
    search_generator
)
from typing import (
    BinaryIO, Union, NoReturn, Callable,
    AsyncGenerator, List, Dict, Optional
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
    'TelegramClient', 
    'EncryptedRemoteBox',
    'DecryptedRemoteBox',
    'EncryptedRemoteBoxFile', 
    'DecryptedRemoteBoxFile', 
    'EncryptedLocalBox', 
    'DecryptedLocalBox', 
    'EncryptedLocalBoxDirectory',
    'DecryptedLocalBoxDirectory',
    'EncryptedLocalBoxFile', 
    'DecryptedLocalBoxFile', 
    'DirectoryRoot',
    'PreparedFile'
]
TelegramClient.__version__ = VERSION

class TelegramClient(TelegramClient):
    """
    A little extend to the ``telethon.TelegramClient``.

    This class inherits Telethon's TelegramClient and support
    all features that has ``telethon.TelegramClient``.
    
    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import TelegramClient, make_remote_box
        from getpass import getpass # For hidden input
        
        PHONE_NUMBER = '+10000000000' # Your phone number
        API_ID = 1234567 # Your API_ID: my.telegram.org
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
            erb = await make_remote_box(tc)

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
                ``TelegramClient.session.save()`` method.

            You should specify at least ``session`` or ``phone_number``.
        """
        if not session and not phone_number:
            raise ValueError(
                'You should specify at least ``session`` or ``phone_number``.'
            )
        super().__init__(
            StringSession(session), 
            api_id, api_hash
        )
        self._api_id, self._api_hash = api_id, api_hash
        self._phone_number = phone_number
        
    async def send_code(self, force_sms: Optional[bool]=False) -> SentCode:
        """
        Sends the Telegram code needed to login to the given phone number.
        
        Arguments:
            force_sms (``bool``, optional):
                Whether to force sending as SMS.
        """
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
        if not await self.is_user_authorized():
            try:
                await self.sign_in(self._phone_number, code)
            except SessionPasswordNeededError:
                await self.sign_in(password=password)

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
        return await self(ResendCodeRequest(
            self._phone_number, sent_code.phone_code_hash)
        )
    async def tgboxes(self, yield_with: str=REMOTEBOX_PREFIX) -> AsyncGenerator:
        """
        Iterate over all Tgbox Channels in your account.
        It will return any channel with Tgbox prefix,
        ``.defaults.REMOTEBOX_PREFIX`` by default, 
        you can override this with ``yield_with``.
        
        Arguments:
            yield_with (``str``):
                Any channel that have ``in`` title this
                string will be returned as ``RemoteBox``. 
        """
        async for d in self.iter_dialogs():
            if yield_with in d.title and d.is_channel: 
                yield EncryptedRemoteBox(d, self)

async def make_remote_box(
        tc: 'TelegramClient', 
        tgbox_db_name: str=DEF_TGBOX_NAME,
        tgbox_rb_prefix: str=REMOTEBOX_PREFIX,
        box_image_path: Union[PathLike, str] = BOX_IMAGE_PATH,
        box_salt: Optional[bytes] = None) -> 'EncryptedRemoteBox':
    """
    Function used for making ``RemoteBox``. 
    
    Arguments:
        tc (``TelegramClient``):
            Account to make private Telegram channel.
            You must be signed in via ``log_in()``.
        
        tgbox_db_name (``TgboxDB``, optional):
            Name of your Local and Remote boxes.
            ``defaults.DEF_TGBOX_NAME`` by default.

        tgbox_rb_prefix (``str``, optional):
            Prefix of your RemoteBox.
            ``defaults.REMOTEBOX_PREFIX`` by default.

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
    if (await tgbox_db.BOX_DATA.count_rows()): 
        raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

    channel_name = tgbox_rb_prefix + tgbox_db.name
    box_salt = urlsafe_b64encode(box_salt if box_salt else get_rnd_bytes())

    channel = (await tc(CreateChannelRequest(
        channel_name,'',megagroup=False))).chats[0]
    
    if box_image_path:
        box_image = await tc.upload_file(open(box_image_path,'rb'))
        await tc(EditPhotoRequest(channel, box_image)) 

    await tc(EditChatAboutRequest(channel, box_salt.decode()))
    return EncryptedRemoteBox(channel, tc)

async def get_remote_box(
        dlb: Optional['DecryptedLocalBox'] = None, 
        tc: Optional['TelegramClient'] = None,
        entity: Optional[Union[int, str, PeerChannel]] = None)\
        -> Union['EncryptedRemoteBox', 'DecryptedRemoteBox']:
    """
    Returns ``EncryptedRemoteBox`` or 
    ``DecryptedRemoteBox`` if you specify ``dlb``.
    
    .. note::
        Must be specified at least ``dlb`` or ``tc`` with ``entity``. 
    
    Arguments:
        dlb (``DecryptedLocalBox``, optional):
            Should be specified if ``tc`` is ``None``.

        tc (``TelegramClient``, optional):
            Should be specified if ``dlb`` is ``None``.
            ``entity`` should be specified with ``tc``.

            Note that ``tc`` must be already connected 
            with Telegram via ``await tc.connect()``.

        entity (``PeerChannel``, ``int``, ``str``, optional):
            Can be ``Channel`` ID, Username or ``PeerChannel``.
            Will be used if specified. Must be specified with ``tc``.
    """
    if tc:
        account = tc

    elif tc and not entity:
        raise ValueError('entity must be specified with tc')
    else:
        account = TelegramClient(
            session=dlb._session,
            api_id=dlb._api_id,
            api_hash=dlb._api_hash
        )
        await account.connect()
    try:
        entity = entity if entity else PeerChannel(dlb._box_channel_id)
        channel_entity = await account.get_entity(entity)
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
        basekey: BaseKey) -> 'DecryptedLocalBox':
    """
    Makes LocalBox

    Arguments:
        erb (``RemoteBox``):
            ``EncryptedRemoteBox``. You will
            recieve it after ``make_remote_box``.

        basekey (``BaseKey``):
            ``BaseKey`` that will be used 
            for ``MainKey`` creation. 
    """
    tgbox_db = await TgboxDB.create(await erb.get_box_name())
    if (await tgbox_db.BOX_DATA.count_rows()): 
        raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

    box_salt = await erb.get_box_salt()
    mainkey = make_mainkey(basekey, box_salt)
    
    await tgbox_db.BOX_DATA.insert(
        AES(mainkey).encrypt(int_to_bytes(erb._box_channel_id)),
        AES(mainkey).encrypt(int_to_bytes(int(time()))),
        box_salt,
        None, # We aren't cloned box, so Mainkey is empty
        AES(basekey).encrypt(erb._tc.session.save().encode()), 
        AES(mainkey).encrypt(int_to_bytes(erb._tc._api_id)),
        AES(mainkey).encrypt(bytes.fromhex(erb._tc._api_hash)),
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
            is ``defaults.DEF_TGBOX_NAME``.
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
            TelegramClient, 
            make_local_box, 
            make_remote_box
        )
        from getpass import getpass
        from asyncio import run as asyncio_run
        
        PHONE_NUMBER = '+10000000000' # Your phone number
        API_ID = 1234567 # Your own API_ID: my.telegram.org
        API_HASH = '00000000000000000000000000000000' # Your own API_HASH
        
        async def main():
            # Connecting and logging to Telegram
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
            # Making base RemoteBox (EncryptedRemoteBox)
            erb = await make_remote_box(tc)

        asyncio_run(main())
    """
    def __init__(self, box_channel: Channel, tc: TelegramClient):
        """
        Arguments:
            box_channel (``Channel``):
                Telegram channel that represents
                RemoteBox. By default have 
                ``.defaults.REMOTEBOX_PREFIX`` in name
                and always encoded by urlsafe
                b64encode BoxSalt in description.

            tc (``TelegramClient``):
                Telegram account that have ``box_channel``.
        """
        self._tc = tc

        self._box_channel = box_channel
        self._box_channel_id = box_channel.id

        self._box_salt = None 
        # We can't use await in __init__, so 
        # you should await get_box_salt firstly.
        self._box_name = None
        # Similar to box_salt, await get_box_name.

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
        see *"Events Reference"* in Telethon Docs.
        """
        return events.NewMessage(chats=self.box_channel_id)

    @property
    def tc(self) -> TelegramClient:
        """Returns ``TelegramClient``"""
        return self._tc

    @property
    def box_channel(self) -> Channel:
        """Returns instance of ``Channel``"""
        return self._box_channel
    
    @property
    def box_channel_id(self) -> int:
        """Returns box channel id"""
        return self._box_channel_id
    
    async def get_last_file_id(self) -> int:
        """Returns last channel file id. If nothing found returns 0"""
        async for msg in self._tc.iter_messages(self._box_channel):
            if not msg: 
                continue
            if msg.document: 
                return msg.id
        return 0

    async def get_box_salt(self) -> bytes:
        """
        Returns BoxSalt. Will be cached 
        after first method call.
        """
        if not self._box_salt:
            full_rq = await self._tc(GetFullChannelRequest(channel=self._box_channel))
            self._box_salt = urlsafe_b64decode(full_rq.full_chat.about)
            
        return self._box_salt
    
    async def get_box_name(self):
        """
        Returns name of ``RemoteBox``. 
        Will be cached after first method call.
        """
        if not self._box_name:
            entity = await self._tc.get_entity(self._box_channel_id)
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
        if hasattr(self, '_mainkey') and not key:
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
            cache_preview: bool=True,
            erase_encrypted_metadata: bool=True) -> AsyncGenerator[
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

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent 
                ``EncryptedRemoteBoxFile`` after decryption 
                to save more RAM if ``True``. You can call 
                ``.init()`` method on it to load it again.
        """
        if hasattr(self, '_mainkey') and not key:
            key = self._mainkey

        if hasattr(self, '_dlb'):
            dlb = self._dlb

        if decrypt and not any((key, dlb)):
            raise ValueError(
                'You need to specify key or dlb to be able to decrypt.'
            )
        key = key if (key or not dlb) else dlb._mainkey
        
        it_messages = self._tc.iter_messages(
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
                        m, self._tc, cache_preview=cache_preview).init()
                else:
                    try:
                        rbf = await EncryptedRemoteBoxFile(
                            m, self._tc, cache_preview=cache_preview).decrypt(
                                key, erase_encrypted_metadata)
                    except Exception as e: # In case of imported file
                        if return_imported_as_erbf and not dlb:
                            rbf = await EncryptedRemoteBoxFile(
                                m, self._tc, cache_preview=cache_preview).init()

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
                                        m, self._tc, cache_preview=cache_preview).init()
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
                                    m, self._tc, cache_preview=cache_preview
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

        it_messages = self._tc.iter_messages(
            self._box_channel, min_id=min_id, 
            max_id=max_id, reverse=True
        )
        sgen = search_generator(
            sf, mainkey=mainkey, 
            it_messages=it_messages, 
            lb=dlb, tc=self._tc
        )
        async for file in sgen:
            yield file

    async def push_file(
            self, pf: 'PreparedFile', 
            progress_callback: Optional[Callable[[int, int], None]] = None,
            ) -> 'DecryptedRemoteBoxFile':
        """
        Uploads ``PreparedFile`` to the ``RemoteBox``.
        
        Arguments:
            pf (``PreparedFile``):
                PreparedFile to upload. You should recieve
                it via ``DecryptedLocalBox.prepare_file``.

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters: 
                (downloaded_bytes, total). 
        """
        # Last 16 bytes of metadata is IV
        state = AES(pf.filekey, pf.metadata[-16:])
        
        oe = OpenPretender(pf.file, state, pf.filesize)
        oe.concat_metadata(pf.metadata)
        try:
            ifile = await upload_file(
                self._tc, oe,
                file_name=urlsafe_b64encode(pf.filesalt).decode(), 
                part_size_kb=512, file_size=pf.filesize,
                progress_callback=progress_callback
            )
        except FilePartsInvalidError:
            raise LimitExceeded('Your file is too big to upload')
        try:
            file_message = await self._tc.send_file(
                self._box_channel, file=ifile, 
                silent=False, force_document=True
            )
        except ChatAdminRequiredError:
            box_name = await self.get_box_name()
            raise NotEnoughRights(
                '''You don\'t have enough privileges to upload '''
               f'''files to remote {box_name}. Ask for it or '''
                '''use this box as read only.'''
            ) from None

        pf.set_file_id(file_message.id)
        pf.set_upload_time(int(file_message.date.timestamp()))

        await pf.dlb._make_local_file(pf)
        
        erbf = await EncryptedRemoteBoxFile(file_message, self._tc).init()
        return await erbf.decrypt(pf.dlb._mainkey)

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
        await self._tc.delete_dialog(
            self._box_channel)

    async def delete(self) -> None:
        """
        This method **WILL DELETE** *RemoteBox*.

        Use ``left()`` if you only want to left
        from ``Channel``, not delete it.

        You need to have rights for this.
        """
        try:
            await self._tc(DeleteChannelRequest(self._box_channel)) 
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
    
    async def done(self):
        """
        Await this method when you end all
        work with RemoteBox, so we will
        clean up & close connections.
        """
        await self._tc.disconnect()

class DecryptedRemoteBox(EncryptedRemoteBox):
    """
    *RemoteBox* is a remote cloud storage. You can
    upload files and download them later.

    Locally we only keep info about files (in *LocalBox*).
    You can fully restore your LocalBox from RemoteBox.

    This class represents decrypted RemoteBox, you can
    iterate over all decrypted files, clone and upload.
    
    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box, get_remote_box
        from tgbox.keys import make_basekey, Phrase
    
        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)
        
        async def main():
            dlb = await dlb.get_local_box(basekey)
            drb = await get_remote_box(dlb)
            
            # Make a PreparedFile
            pf = await dlb.prepare_file(open('cats.jpg','rb'))

            # Waiting file for upload, return DecryptedRemoteBoxFile
            drbf = await drb.push_file(pf)

            # Get some info
            print(drbf.file_name, drbf.size)

            # Remove file from RemoteBox
            await drbf.delete()
            
            # Check if file exists
            print(await drb.file_exists(drbf.id)

        asyncio_run(main())
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
        self._erb = erb
        self._tc = erb._tc

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
                (current_amount, total). 

            box_path (``PathLike``, ``str``, optional):
                Direct path with filename included. If
                not specified, then ``RemoteBox`` name used.
        """
        box_path = await self.get_box_name()\
            if not box_path else box_path

        tgbox_db = await TgboxDB.create(box_path)

        if (await tgbox_db.BOX_DATA.count_rows()): 
            raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')
        
        last_file_id = 0
        async for erbf in self.files(decrypt=False, return_imported_as_erbf=True):
            last_file_id = erbf.id; break

        await tgbox_db.BOX_DATA.insert(
            AES(self._mainkey).encrypt(int_to_bytes(self._box_channel_id)),
            AES(self._mainkey).encrypt(int_to_bytes(int(time()))),
            await self.get_box_salt(),
            AES(basekey).encrypt(self._mainkey.key),
            AES(basekey).encrypt(self._tc.session.save().encode()),
            AES(self._mainkey).encrypt(int_to_bytes(self._tc._api_id)),
            AES(self._mainkey).encrypt(bytes.fromhex(self._tc._api_hash)),
        )
        dlb = await EncryptedLocalBox(tgbox_db).decrypt(basekey)
        
        files_generator = self.files(
            key=self._mainkey, 
            decrypt=True, reverse=True,
            erase_encrypted_metadata=False
        )
        async for drbf in files_generator:
            if progress_callback:
                if iscoroutinefunction(progress_callback):
                    await progress_callback(drbf.id, last_file_id)
                else:
                    progress_callback(drbf.id, last_file_id)
            
            await dlb.import_file(drbf)
        
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
    Verbyte, BoxSalt, FileSalt, sender & etc.

    More information you can get from docs.
    Typically you don't need to use this class.

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
            print(erbf.file_salt.hex())
            print(erbf.box_salt.hex())

        asyncio_run(main())
    """
    def __init__(
            self, sended_file: Message, 
            tc: TelegramClient, 
            cache_preview: bool=True):
        """
        Arguments:
            sended_file (``Message``):
                A ``Telethon``'s message object. This
                message should contain ``File``.

            tc (``TelegramClient``):
                Your Telegram account.

            cache_preview (``bool``, optional):
                Cache preview in class or not. ``True`` by default. 
                This kwarg will be used later in ``DecryptedRemoteBoxFile``
        """
        self._initialized = False
        
        self._metadata = None
        self._message = sended_file

        self._id = sended_file.id
        self._file = sended_file.file
        
        if not self._file:
            raise NotATgboxFile('Specified message doesn\'t have a document')

        self._sender = sended_file.post_author
        
        self._tc = tc
        self._cache_preview = cache_preview
        
        self._upload_time = int(self._message.date.timestamp()) 
        self._box_channel_id = sended_file.peer_id.channel_id
        self._file_size = self._file.size
        self._file_file_name = self._file.name
        
        self._file_iv = None
        self._box_salt = None
        self._version_byte = None
        self._prefix = None

        if self._message.fwd_from:
            self._exported = True            
        else:
            self._exported = False
    
    def __hash__(self) -> int:
        if not self.initialized:
            raise NotInitializedError(
                'Must be initialized before hashing'
            )
        if isinstance(self, DecryptedRemoteBoxFile): 
            return hash((self._id, self._file_name))
        else:
            return hash((self._id, self._file_file_name))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def initialized(self) -> bool:
        """Returns ``True`` if class was initialized."""
        return self._initialized

    @property
    def tc(self) -> TelegramClient:
        """Returns ``TelegramClient``"""
        return self._tc
    
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
    def file_iv(self) -> Union[bytes, None]:
        """Returns File IV or ``None`` if not initialized"""
        return self._file_iv

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
    
    async def init(self, verify_prefix: bool=True) -> 'EncryptedRemoteBoxFile':
        """
        This method will download and set raw
        RemoteBoxFile metadata. If metadata length
        is bigger than ``defaults.METADATA_MAX``
        then ``errors.LimitExceeded`` will be raised.

        Arguments:
            verify_prefix (``bool``, optional):
                If ``True``, will check that file has a
                ``defaults.PREFIX`` in metadata, and if 
                not, will raise a ``NotATgboxFile`` exception.
        """
        # 3 is amount of bytes to which we pack metadata length
        request_amount = len(PREFIX) + len(VERBYTE) + 3

        async for base_data in self._tc.iter_download(
            self._message.document, request_size=pad_request_size(request_amount)):
                base_data = base_data[:request_amount]

                self._prefix = bytes(base_data[:len(PREFIX)])
                self._version_byte = bytes(base_data[len(PREFIX):len(PREFIX)+1])

                if verify_prefix and self._prefix != PREFIX:
                    raise NotATgboxFile(
                        f'''Invalid prefix! Expected {PREFIX}, '''
                        f'''got {self._prefix}'''
                    )
                metadata_size = bytes_to_int(
                    base_data[request_amount-3:request_amount]
                )
                if metadata_size > METADATA_MAX:
                    raise LimitExceeded(f'{METADATA_MAX=}, {metadata_size=}.')

                # We will also download IV. It's not included 
                # in the total metadata bytesize.
                metadata_size += 16
                break
        
        if metadata_size > METADATA_MAX:
            raise LimitExceeded(f'{metadata_size=} > {METADATA_MAX=}')
        
        iter_down = self._tc.iter_download(
            file = self._message.document, 
            offset = request_amount, 
            request_size = pad_request_size(metadata_size)
        )
        async for metadata in iter_down:
            m = self._prefix + self._version_byte
            m += int_to_bytes(metadata_size,3)
            self._metadata = m + bytes(metadata[:metadata_size])
            break
        
        parsedm = PackedAttributes.unpack(self._metadata[len(m):-16])
        
        self._file_salt = parsedm['file_salt']
        self._box_salt = parsedm['box_salt']
        self._file_iv = self._metadata[-16:]

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
        rm_result = await self._tc.delete_messages(
            self._box_channel_id, [self._id]
        )
        if not rm_result[0].pts_count:
            raise NotEnoughRights(
                '''You don\'t have enough rights to delete '''
                '''file from this RemoteBox.'''
            )
    
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
            self, key: Union[MainKey, FileKey, ImportKey, BaseKey],
            erase_encrypted_metadata: Optional[bool] = True
            ) -> 'DecryptedRemoteBoxFile':
        """
        Returns ``DecryptedRemoteBoxFile``.
        
        Arguments:
            key (``MainKey``, ``FileKey``, ``ImportKey``, ``BaseKey``):
                Decryption key. All, except ``FileKey`` will be
                used to make ``FileKey`` for this file.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent 
                ``EncryptedRemoteBoxFile`` after decryption 
                to save more RAM if ``True``. You can call 
                ``.init()`` method on it to load it again.
        """
        if not self.initialized:
            await self.init()
        return await DecryptedRemoteBoxFile(self, key).init(
            erase_encrypted_metadata=erase_encrypted_metadata)

class DecryptedRemoteBoxFile(EncryptedRemoteBoxFile):
    """
    This class represents decrypted remote file.
    You can retrieve all metadata info from properties.

    Typical usage:

    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box, get_remote_box
        from tgbox.keys import Phrase, make_basekey

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)
        
        async def main():
            dlb = await get_local_box(basekey)
            drb = await get_remote_box(dlb)

            drbf = await drb.get_file(
                id = await dlb.get_last_file_id()
            )
            print(drbf.file_name)

            # Save file preview
            with open(f'preview_{drbf.file_name}','wb') as f:
                f.write(drbf.preview)

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
        
        self.__required_metadata = [
            'duration', 'file_size', 'file_name', 
            'cattrs', 'mime', 'efile_path', 'preview'
        ]
        self._message = erbf._message
        self._id = erbf._id
        self._file = erbf._file
        self._sender = erbf._sender
        
        self._tc = erbf._tc
        self._cache_preview = erbf._cache_preview
        
        self._box_salt = erbf._box_salt
        self._box_channel_id = erbf._box_channel_id
        self._file_size = erbf._file_size
        
        self._upload_time, self._size = erbf._upload_time, None
        self._file_iv, self._file_salt = erbf._file_iv, erbf._file_salt
        self._cattrs, self._file_path = None, None
        self._duration, self._version_byte = None, erbf._version_byte

        self._preview, self._exported = None, erbf._exported
        self._prefix, self._file_pos = erbf._prefix, None

        self._file_file_name = erbf._file_file_name
        self._residual_metadata = None
        
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
    def preview(self) -> Union[bytes, None]:
        """Returns preview bytes or ``None`` if not initialized."""
        return self._preview
    
    @property
    def file_iv(self) -> Union[bytes, None]:
        """Returns file IV or ``None`` if not initialized."""
        return self._file_iv
    
    @property
    def mime(self) -> Union[str, None]:
        """Returns MIME type or ``None`` if not initialized"""
        return self._mime

    @property
    def cattrs(self) -> Union[dict, None]:
        """
        Returns custom attributes or 
        ``None`` if not initialized
        """
        return self._cattrs
    
    @property
    def file_path(self) -> Union[Path, None]:
        """Returns file path or ``None`` if not initialized."""
        return self._file_path

    def set_file_path(self, file_path: Path) -> None:
        self._file_path = file_path

    @property
    def file_name(self) -> Union[bytes, None]:
        """Returns file name or ``None`` if not initialized."""
        return self._file_name

    @property
    def file_iv(self) -> Union[bytes, None]:
        """Returns file iv or ``None`` if not initialized."""
        return self._file_iv

    @property
    def file_salt(self) -> Union[bytes, None]:
        """Returns file salt or ``None`` if not initialized."""
        return self._file_salt

    @property
    def residual_metadata(self) -> Union[dict, None]:
        """
        Will return metadata that left after
        parsing secret_metadata. This can be
        useful in future, when lower version
        will read file of a higher version.

        Will always return ``None`` if
        DRBFI wasn't initialized.
        """
        return self._residual_metadata

    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')
    
    async def init(
            self, cache_preview: bool=True,
            erase_encrypted_metadata: Optional[bool] = True
        ) -> 'DecryptedRemoteBoxFile':
        """
        This method will decrypt and parse metadata from
        the EncryptedRemoteBoxFile.
        
        This method will remove metadata from 
        the parent EncryptedRemoteBoxFile
        to save more RAM if ``erase_encrypted_metadata``
        is specified. You can call .init() method
        on it to load it again.

        If ERBFI wasn't initialized, this
        method will init it.

        If ``cache_preview`` was disabled in the
        parent class then you can set similar kwarg
        here to ``True`` and method will save it.
        """
        if not self._erbf._initialized:
            await self._erbf.init()
        
        cache_preview = cache_preview if cache_preview else self._cache_preview
        pattr_offset = len(PREFIX) + len(VERBYTE) + 3

        unpacked_metadata = PackedAttributes.unpack(
            bytes(self._erbf._metadata[pattr_offset:-16])
        )
        self._file_pos = len(self._erbf._metadata)
        
        secret_metadata = AES(self._filekey).decrypt(
            unpacked_metadata['secret_metadata']
        )
        secret_metadata = PackedAttributes.unpack(secret_metadata)

        if not secret_metadata: # secret_metadata can't be empty dict
            raise AESError('Metadata wasn\'t decrypted correctly. Incorrect key?')
        
        if cache_preview:
            self._preview = secret_metadata['preview']
        else:
            secret_metadata.pop('preview')
            self._preview = b''

        self._duration = bytes_to_int(secret_metadata['duration'])
        self._size = bytes_to_int(secret_metadata['file_size'])
        self._file_name = secret_metadata['file_name']
        self._cattrs = PackedAttributes.unpack(secret_metadata['cattrs'])
        self._mime = secret_metadata['mime'].decode()

        if self._mainkey:
            self._file_path = AES(self._mainkey).decrypt(
                secret_metadata['efile_path']
            )
            self._file_path = Path(self._file_path.decode())
        else:
            self._file_path = None
        
        for attr in self.__required_metadata:
            secret_metadata.pop(attr)

        self._residual_metadata = secret_metadata
        
        if self._message.message:
            try:
                edited_metadata = AES(self._filekey).decrypt(
                    urlsafe_b64decode(self._message.message)
                )
                edited_metadata = PackedAttributes.unpack(edited_metadata)

                for k,v in tuple(edited_metadata.items()):
                    if k in self.__required_metadata:
                        setattr(self, f'_{k}', v)
                    else:
                        self._residual_metadata[k] = v

                    del edited_metadata[k]

            except (TypeError, ValueError):
                # Caption is not an updated metadata. 
                # TODO: Log this in future.
                pass

        self._initialized = True

        if erase_encrypted_metadata:
            self._erbf._initialized = False
            self._erbf._metadata = None

        return self
    
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
                will be downloaded. ``.defaults.DOWNLOAD_PATH`` by default.
                
                If ``outfile`` has ``.write()`` method then we will use it.
            
            hide_folder (``bool``, optional):
                Saves to folder which this file belongs to if False,
                (default) otherwise to ``outfile/{defaults.DEF_UNK_FOLDER}``.
                
                * Doesn't create any folders if ``isinstance(outfile, BinaryIO)``.
            
            hide_name (``bool``, optional):
                Saves file with random name if ``True``, with
                original if ``False`` (default). 

                * File extension (e.g ``.png``) included in both cases.
                * Doesn't create any folders if ``isinstance(outfile, BinaryIO)``.
            
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
            outfile = Path(outfile)
            outfile.mkdir(exist_ok=True)

            path = DEF_UNK_FOLDER if hide_folder else self._file_path
            # The first '/' symbol in '/home/non/' is also path part,
            # so we need to create a folders like / -> home -> non,
            # however, Linux (and i believe all Unix) OS doesn't allow
            # to use a '/' symbol in filename, so instead of / we use
            # a '@' while creating path. You can refer to it as root.
            path = str(DEF_NO_FOLDER if not path else path)
            #
            if path.startswith('/'):
                path = str(Path('@', path.lstrip('/')))
            #
            if hide_name:
                name = prbg(16).hex() + Path(self._file_name.decode()).suffix
            else:
                name = self._file_name.decode()
            
            outfile = Path(outfile, path, name.lstrip('/'))
            outfile.parent.mkdir(exist_ok=True, parents=True)
            outfile = open(outfile,'wb')
            
        elif isinstance(outfile, BinaryIO) or hasattr(outfile, 'write'):
            pass # We already can write 
        else:
            raise TypeError('outfile not Union[BinaryIO, str, PathLike].')
        
        iter_down = download_file(
            client = self._tc,
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
    
    async def update_metadata(
            self, changes: Dict[str, Union[bytes, None]],
            dlb: Optional['DecryptedLocalBox'] = None
        ):
        """This method will "update" file metadata attributes

        Metadata located inside the file, so we can't
        change it in any way except reupload, but we 
        can and we will use its *caption* to place 
        packed by PackedAttributes, encrypted and 
        encoded with ``urlsafe_b64encode`` changes.

        Arguments:
            changes (``Dict[str, Union[bytes, None]]``):
                Metadata changes. You can specify a
                ``None`` as value to remove key from updates.

            dlb (``DecryptedLocalBox``, optional):
                ``DecryptedLocalBox`` associated with
                this ``DecryptedRemoteBox``. Will auto
                refresh your updates. If not specified,
                then you will need to do it by yourself.

        E.g: This code will replace ``file_name`` metadata 
        attribute of the ``DecryptedRemoteBoxFile``

        .. code-block:: python

                ... # Most code is omited, see help(tgbox.api)
                drbf = await drb.get_file(dlb.get_last_file_id())
                await drbf.update_metadata({'file_name': b'new.txt'})

                print(drbf.file_name) # new.txt
        
        .. note::
            - Your LocalBox will NOT know about this update,
              so you should specify here ``dlb`` (is better way) 
              or await the ``refresh_metadata`` method on the 
              ``DecryptedLocalBoxFile`` with the same ID.

            - Not a *default* metadata (like file_name, mime, etc)
              will be placed to the ``residual_metadata`` property dict.

            - There is a file caption (and so updated metadata) 
              limit: 1KB and 2KB for a Premium Telegram users.
            
            - You can replace file's path by specifying a
              ``file_path`` key with appropriate value. Also,
              you **will need** to specify a ``DecryptedLocalBox``
              as ``dlb`` so we can create a new *LocalBoxDirectory*
              from your path. Without it you will get a ``ValueError``
        """
        if 'efile_path' in changes:
            raise ValueError('The "changes" should not contain efile_path')
        
        if 'file_path' in changes and not dlb:
            raise ValueError('You can\'t change file_path without specifying dlb!')
        try:
            message_caption = urlsafe_b64decode(self._message.message)
            updates = AES(self._filekey).decrypt(message_caption)
            updates = PackedAttributes.unpack(updates)
        except (ValueError, TypeError): 
            updates = {}
        
        new_file_path = changes.pop('file_path', None)

        if new_file_path:
            directory = await dlb._make_local_path(Path(new_file_path))

            await dlb._tgbox_db.FILES.execute((
                'UPDATE FILES SET PPATH_HEAD=? WHERE ID=?',
                (directory.part_id, self._id)
            ))
            efile_path = AES(self._mainkey).encrypt(str(new_file_path).encode())
            changes['efile_path'] = efile_path

        updates.update(changes)

        for k,v in tuple(updates.items()):
            if not v: 
                del updates[k]

                if k in self._residual_metadata: 
                    del self._residual_metadata[k]
        
        updates_packed = PackedAttributes.pack(**updates)
        updates_encrypted = AES(self._filekey).encrypt(updates_packed)
        try:
            await self._message.edit(
                urlsafe_b64encode(updates_encrypted).decode()
            )
        except MediaCaptionTooLongError:
            raise NoPlaceLeftForMetadata(NoPlaceLeftForMetadata.__doc__) from None
        except ChatAdminRequiredError:
            raise NotEnoughRights(NotEnoughRights.__doc__) from None
        
        for k,v in tuple(updates.items()):
            if k in self.__required_metadata:
                if k == 'cattrs':
                    setattr(self, f'_{k}', PackedAttributes.unpack(v))
                elif k == 'efile_path':
                    self._file_path = new_file_path
                else:
                    setattr(self, f'_{k}', v)
            else:
                self._residual_metadata[k] = v

        if dlb:
            dlbfi = await dlb.get_file(self._id)
            await dlbfi.refresh_metadata(_updated_metada=updates_encrypted)

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
            
            # Retrieve encrypted session or None
            print(elb.session)
        
        asyncio_run(main())

    You can acces it from the ``DecryptedLocalBox``:

    .. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box
        from tgbox.keys import make_basekey, Phrase
        
        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
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
    
    async def get_last_file_id(self) -> int:
        """
        Returns last file id from the FILES table.
        If there is no files at all, will return 0.
        """
        try:
            lfi = await self._tgbox_db.FILES.select_once((
                'SELECT ID FROM FILES ORDER BY ID DESC LIMIT 1', ()
            ))
            return lfi[0]
        except StopAsyncIteration:
            return 0

    async def init(self) -> 'EncryptedLocalBox':
        """Will fetch and parse data from Database."""

        if not await self._tgbox_db.BOX_DATA.count_rows():
            raise NotInitializedError('Table is empty.') 
        else:
            box_data = await self._tgbox_db.BOX_DATA.select_once()
            self._box_channel_id = box_data[0]
            self._box_cr_time, self._box_salt, self._mainkey = box_data[1:4]
            self._session, self._initialized = box_data[4], True
            self._api_id, self._api_hash = box_data[5], box_data[6]

            if self._mainkey:
                self._mainkey = EncryptedMainkey(self._mainkey)

        return self

    async def get_file(
            self, id: int, decrypt: bool=True, cache_preview: bool=True)\
            -> Union['DecryptedLocalBoxFile', 'EncryptedLocalBoxFile', None]:
        """
        Returns ``EncryptedLocalBoxFile`` from ``EncryptedLocalBox``
        or ``DecryptedLocalBoxFile`` from ``DecryptedLocalBox`` if
        file exists. ``None`` otherwise.
        
        Arguments:
            id (``int``):
                File ID.

            decrypt (``bool``, optional):
                Force return EncryptedLocalBoxFile

            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        try:
            self.__raise_initialized()
            elbf = EncryptedLocalBoxFile(
                id, self._tgbox_db, 
                cache_preview=cache_preview
            )
            if decrypt and self._mainkey and not\
                isinstance(self._mainkey, EncryptedMainkey):
                    return await elbf.decrypt(self._mainkey)
            else:
                return await elbf.init()
        except StopAsyncIteration: # No file by ``id``.
            return None
    
    async def contents(
            self, sfpid: Optional[bytes] = None,
            ignore_files: Optional[bool] = False
                ) -> AsyncGenerator[Union[
                'EncryptedLocalBoxDirectory', 
                'DecryptedLocalBoxDirectory'], None
            ]:
        """
        Recursive iterate over all files/folders in LocalBox.

        Arguments:
            sfpid (``bytes``, optional):
                Will start from this PartID if specified,
                else will start from "root" PIDs.

            ignore_files (``bool``, optional):
                Will return LocalBoxFile associated 
                with LocalBoxDirectory if ``False``.
        """
        sfpid = (sfpid,) if sfpid else []

        if not sfpid:
            root_pids = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT PART_ID FROM PATH_PARTS WHERE PARENT_PART_ID IS NULL', () 
            ))
            sfpid = [i[0] for i in await root_pids.fetchall()]
        
        current_lbfid = None

        for pid in sfpid:
            lbfid = EncryptedLocalBoxDirectory(self._tgbox_db, pid)

            if isinstance(self, DecryptedLocalBox):
                lbfid = await lbfid.decrypt(self._mainkey)
            else:
                lbfid = await lbfid.init()
            
            yield lbfid
            
            if not ignore_files:
                async for lbfi in lbfid.iterdir(ignore_dirs=True):
                    yield lbfi

            child_pids = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT PART_ID FROM PATH_PARTS WHERE PARENT_PART_ID IS ?',
                (pid,) 
            ))
            child_sfpid = [i[0] for i in await child_pids.fetchall()]
            
            for csfpid in child_sfpid:
                contents = self.contents(csfpid, ignore_files=ignore_files)
                async for content in contents:
                    yield content 
    
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

        Alternatively, you may use LocalBox.contents method.
        
        Arguments:
            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        min_id = f'ID > {min_id}' if min_id else ''
        max_id = f'ID < {max_id}' if max_id else ''
        
        min_id = min_id + ' AND' if all((min_id,max_id)) else min_id
        where = 'WHERE' if any((min_id, max_id)) else ''

        sql_query = f'SELECT ID FROM FILES {where} {min_id} {max_id}'
        cursor = await self._tgbox_db.FILES.execute((sql_query ,()))

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
    
    async def delete(self) -> None:
        """
        This method **WILL DELETE** your *LocalBox* 
        database. It doesn't affect *RemoteBox*,
        so you can make new *LocalBox* from the
        *Remote* version if you have *MainKey*.

        Will raise ``FileNotFoundError`` if
        something goes wrong (i.e DB was moved).
        """
        if not self._tgbox_db.closed:
            await self.done()

        self._tgbox_db.db_path.unlink()

    async def decrypt(self, key: Union[BaseKey, MainKey]) -> 'DecryptedLocalBox':
        """Will return ``DecryptedLocalBox``.

        You **should** specify ``BaseKey`` if you
        want to access session and use this dlb
        with *RemoteBox*, however, you can specify
        ``MainKey`` if you only want to iterate
        over local files / fetch basic local info.
        """
        if not self.initialized: await self.init()
        return DecryptedLocalBox(self, key)

    async def done(self):
        """
        Await this method when you end all
        work with LocalBox, so we will
        clean up & close connections.
        """
        await self._tgbox_db.close()

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
        from tgbox.api import get_local_box, DecryptedLocalBoxFile
        from tgbox.keys import make_basekey, Phrase
        
        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_local_box(basekey)
            
            # Iterate over LocalBox contents 
            async for content in dlb.contents(ignore_files=False):
                if isinstance(content, DecryptedLocalBoxFile):
                    print('File:', file.id, file.file_name, file.size)
                else:
                    await content.lload(full=True) # Load directory
                    print('Dir:', content, content.part_id.hex())

        asyncio_run(main())
    """
    def __init__(self, elb: EncryptedLocalBox, key: Union[BaseKey, MainKey]):
        """
        Arguments:
            elb (``EncryptedLocalBox``):
                Local box you want to decrypt.

            key (``BaseKey``, ``MainKey``):
                You **should** specify ``BaseKey`` if you
                want to access session and use this dlb
                with *RemoteBox*, however, you can specify
                ``MainKey`` if you only want to iterate
                over local files / fetch basic local info.
        """
        if not elb.initialized:
            raise NotInitializedError('Parent class isn\'t initialized.')

        self._elb = elb
        self._tgbox_db = elb._tgbox_db
        self._initialized = True 
        
        if isinstance(key, BaseKey):
            if isinstance(elb._mainkey, EncryptedMainkey):
                mainkey = AES(key).decrypt(elb._mainkey.key)
                self._mainkey = MainKey(mainkey)
            else:
                self._mainkey = make_mainkey(key, self._elb._box_salt)
            try:
                # We encrypt Session with Basekey to prevent stealing 
                # Session information by people who also have mainkey 
                # of the same box. So there is decryption with basekey.
                self._session = AES(key).decrypt(elb._session).decode()
            except UnicodeDecodeError:
                raise IncorrectKey('Can\'t decrypt Session. Invalid Basekey?') 
        
        elif isinstance(key, MainKey):
            self._mainkey = key
            self._session = None
        else:
            raise IncorrectKey('key is not Union[BaseKey, MainKey]')
        
        self._box_channel_id = bytes_to_int(
            AES(self._mainkey).decrypt(elb._box_channel_id)
        )
        self._box_cr_time = bytes_to_int(
            AES(self._mainkey).decrypt(elb._box_cr_time)
        )
        self._api_id = bytes_to_int(
            AES(self._mainkey).decrypt(elb._api_id)
        )
        self._api_hash = AES(self._mainkey).decrypt(elb._api_hash)
        self._box_salt = elb._box_salt

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
    async def _make_local_path(self, file_path: Path) -> 'DecryptedLocalBoxDirectory':
        """
        Creates abstract LocalBoxDirectory, and returns
        the ``DecryptedLocalBoxDirectory`` object.

        Arguments:
            file_path (``Path``):
                File path. No filename included.
        """
        ppidg = ppart_id_generator(file_path, self._mainkey)

        for part, parent_part_id, part_id in ppidg:
            if not parent_part_id: 
                parent_part_id = None

            cursor = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT PART_ID FROM PATH_PARTS WHERE PART_ID=?', (part_id,))
            )
            if not await cursor.fetchone():
                await self._tgbox_db.PATH_PARTS.insert(
                    AES(self._mainkey).encrypt(part.encode()),
                    part_id, parent_part_id
                )
        elbd = EncryptedLocalBoxDirectory(self._tgbox_db, part_id)
        return await elbd.decrypt(self._mainkey)

    async def _make_local_file(self, pf: 'PreparedFile') -> 'DecryptedLocalBoxFile':
        """
        Creates a LocalBoxFile.
        
        Arguments:
            pf (``PreparedFile``):
                Pushed to RemoteBox ``PreparedFile``.
        """
        assert hasattr(pf,'file_id'), 'Push to RemoteBox firstly'
        assert hasattr(pf,'upload_time'), 'Push to RemoteBox firstly'
        try:
            # Verify that there is no file with the same ID
            maybe_file = await self._tgbox_db.FILES.select_once(
                sql_tuple=('SELECT ID FROM FILES WHERE ID=?', (pf.file_id,))
            )
        except StopAsyncIteration:
            pass
        else:
            raise AlreadyImported('There is already file with same ID') from None
        
        eupload_time = AES(pf.filekey).encrypt(int_to_bytes(pf.upload_time))
        
        if pf.imported:
            if make_filekey(self._mainkey, pf.filesalt) == pf.filekey:
                efilekey = None # We can make it with our MainKey
            else:
                efilekey = AES(self._mainkey).encrypt(pf.filekey.key)
        else:
            efilekey = None
        
        part_id = (await self._make_local_path(pf.filepath)).part_id

        await self._tgbox_db.FILES.insert(
            pf.file_id, eupload_time, part_id, 
            efilekey, pf.metadata, None
        )
        return await EncryptedLocalBoxFile(
            pf.file_id, self._tgbox_db).decrypt(pf.filekey)
    
    # TODO: Delete PartID from PATH_PARTS if it links
    # to only one file that was removed.
    async def sync(
            self, drb: DecryptedRemoteBox, 
            start_from: int=0,
            progress_callback: Optional[Callable[[int, int], None]] = None):
        """
        This method will synchronize your LocalBox
        with RemoteBox. All files that not in RemoteBox
        but in Local will be **removed**, all that 
        in Remote but not in LocalBox will be imported.

        drb (``DecryptedRemoteBox``):
            *RemoteBox* associated with this LocalBox.

        start_from (``int``, optional):
            Will check files that > start_from [ID].

        progress_callback (``Callable[[int, int], None]``, optional):
            A callback function accepting 
            two parameters: (last_id, current_id). 
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
                    await self._tgbox_db.FILES.execute(
                        sql_tuple=('DELETE FROM FILES', ()))
                    break

                rbfiles.append(await _get_file(rbfiles[0].id))
                last_id = rbfiles[0].id

                sql_tuple = (
                    'DELETE FROM FILES WHERE ID < ?', 
                    (last_id,)
                )
                await self._tgbox_db.FILES.execute(
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
                    lbfi_id = await self._tgbox_db.FILES.select_once(
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
                await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)
            
            last_id = rbfiles[1].id if rbfiles[1] else None
            
            if last_id:
                sql_tuple = (
                    'DELETE FROM FILES WHERE ID > ? AND ID < ?',
                    (rbfiles[0].id, rbfiles[1].id)
                )
                if difference(sql_tuple[1]):
                    await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)
            else:
                sql_tuple = (
                    'DELETE FROM FILES WHERE ID = ?',
                    (rbfiles[0].id,)
                )
                await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)
                break

    async def replace_session(
            self, basekey: BaseKey, tc: TelegramClient) -> None:
        """
        This method will replace LocalBox session to
        session of specified ``TelegramClient``.

        Arguments:
            basekey (``BaseKey``):
                ``BaseKey`` of this *LocalBox*.

            tc (``TelegramClient``):
                ``TelegramClient`` from which we
                will extract new session. 
        """
        try:
            AES(basekey).decrypt(self._elb._session).decode()
        except UnicodeDecodeError:
            raise IncorrectKey(
                'BaseKey doesn\'t match with BaseKey of LocalBox') from None
        else:
            self._session = tc.session.save()
            
            session = AES(basekey).encrypt(self._session.encode())
            self._elb._session = session

            sql_tuple = ('UPDATE BOX_DATA SET SESSION = ?',(session,))
            await self._tgbox_db.BOX_DATA.execute(sql_tuple) 

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
        async for file in search_generator(sf, lb=self, mainkey=self._mainkey):
            yield file
        
    async def prepare_file( 
            self, file: Union[BinaryIO, bytes, Document, Photo],
            file_size: Optional[int] = None,
            file_path: Optional[Path] = None,
            cattrs: Optional[Dict[str, Union[bytes]]] = None,
            make_preview: bool=True) -> 'PreparedFile':
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
                
                Abs file path length must be <= ``defaults.FILE_PATH_MAX``;
                If file has no ``name`` and ``file_path`` is not 
                specified then it will be ``NO_FOLDER/{prbg(6).hex()}``.
            
            file_size (``int``, optional):
                Bytelength of ``file``. You can specify
                it if you already know file size.

            file_path (``Path``, optional):
                File path. You can specify here path
                that isn't exists. If not specified, will
                be used path from the ``BinaryIO``, if file
                is not a ``BinaryIO`` then will be used a
                ``defaults.DEF_NO_FOLDER``.

                Must be <= ``defaults.FILE_PATH_MAX``.
            
            cattrs (``Dict[str, Union[bytes, None]]``, optional):
                The file's custom metadata attributes that
                will be added to the main metadata. Specified
                dict will be packed with the PackedAttributes.

                Please note that after some operations we 
                will create a file metadata. Its limit 
                defined as ``defaults.METADATA_MAX``. You
                shouldn't overflow this number plus size of 
                default metadata; other is up to you.

            make_preview (``bool``, optional):
                Will try to add file preview to 
                the metadata if ``True`` (default).
        """
        file_salt, file_iv = get_rnd_bytes(32), get_rnd_bytes(16)
        filekey = make_filekey(self._mainkey, file_salt)

        class TelegramVirtualFile:
            def __init__(self, doc_pic, session):
                self.downloader = None
                self.doc_pic = doc_pic
                
                self.tc = TelegramClient(
                    session=session,
                    api_id=self._api_id,
                    api_hash=self._api_hash
                )
                self.tc = self.tc.connect()
                self._client_initialized = False
                
                file = File(doc_pic)
                self.name = file.name
                self.size = file.size

                self.duration = file.duration\
                    if file.duration else 0
            
            async def get_preview(self, quality: int=1) -> bytes:
                if not self._client_initialized:
                    self.tc = await self.tc # connect
                    self._client_initialized = True
            
                if hasattr(self.doc_pic,'sizes')\
                    and not self.doc_pic.sizes:
                        return b''

                if hasattr(self.doc_pic,'thumbs')\
                    and not self.doc_pic.thumbs:
                        return b''

                return await self.tc.download_media(
                    message = self.doc_pic, 
                    thumb = quality, file = bytes
                )
            async def read(self, size: int) -> bytes:
                if not self._client_initialized:
                    self.tc = await self.tc
                    self._client_initialized = True

                if not self.downloader:
                    self.downloader = download_file(
                        self.tc, self.doc_pic
                    )
                chunk = await anext(self.downloader)
                return chunk

        if isinstance(file, (Document, Photo)):
            if not self._session:
                raise NotEnoughRights(
                    '''You need to decrypt LocalBox with BaseKey, '''
                    '''MainKey is not enough. Session is None.'''
                )
            file = TelegramVirtualFile(file, self._session)
            make_preview = False # We will call get_preview
        
        if file_path is None:
            if hasattr(file,'name') and file.name:
                file_path = Path(file.name).absolute()
            else:
                file_path = Path(DEF_NO_FOLDER, prbg(8).hex())
        else:
            if len(file_path.parts) < 2:
                raise ValueError('Path should contain folder and file name')

        if len(str(file_path)) > FILE_PATH_MAX: 
            raise LimitExceeded(f'File path must be <= {FILE_PATH_MAX} bytes.')
        
        if not file_size:
            if isinstance(file, TelegramVirtualFile):
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
        try:
            mime_type = filetype_guess(file).mime
            file_type = mime_type.split('/')[0]
        except:
            mime_type = ''
            file_type = None
        finally:
            # filetype.guess reads N bytes and
            # doesn't seek back. Thanks to this
            # i spent around 3 hours of debugging.
            file.seek(0,0)

        preview, duration = b'', 0
        
        if isinstance(file, TelegramVirtualFile):
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
        
        # --- Start constructing metadata here --- #

        # We should always encrypt FILE_PATH with MainKey.
        file_path_no_name = str(file_path.parent).encode()
        efile_path = AES(self._mainkey).encrypt(file_path_no_name)
        
        cattrs = PackedAttributes.pack(**cattrs) if cattrs else b''

        secret_metadata = PackedAttributes.pack(
            preview = preview,
            duration = int_to_bytes(duration),
            file_size = int_to_bytes(file_size),
            efile_path = efile_path,
            file_name = file_path.name.encode(),
            mime = mime_type.encode(),
            cattrs = cattrs 
        )
        secret_metadata = AES(filekey).encrypt(secret_metadata)

        metadata = PackedAttributes.pack(
            box_salt = self._box_salt,
            file_salt = file_salt,
            secret_metadata = secret_metadata
        )
        if len(metadata) > METADATA_MAX:
            raise LimitExceeded(
                f'Total len(metadata) must be <= {METADATA_MAX}'
            )
        if len(metadata) > 256**3-1:
            raise LimitExceeded(
                'Total len(metadata) must be <= 256^3-1'
            )
        metadata_bytesize = int_to_bytes(len(metadata),3)
        
        constructed_metadata =  PREFIX + VERBYTE
        constructed_metadata += metadata_bytesize 
        constructed_metadata += metadata + file_iv

        total_file_size = len(constructed_metadata) + file_size
        
        return PreparedFile(
            dlb = self, 
            file = file,
            filekey = filekey,
            filesize = total_file_size,
            filepath = Path(file_path_no_name.decode()),
            filesalt = file_salt,
            metadata = constructed_metadata,
            imported = False
        )
    async def import_file( 
            self, drbf: DecryptedRemoteBoxFile,
            file_path: Optional[Path] = None)\
            -> 'DecryptedLocalBoxFile':
        """
        Imports file to your ``DecryptedLocalBox``

        Arguments:
            drbf (``DecryptedRemoteBoxFile``):
                Remote file you want to import.

            file_path (``Path``, optional):
                File's path. Will be used ``drbf._file_path`` if
                ``None`` and if drbf was decrypted with the 
                ``MainKey``, otherwise ``defaults.DEF_NO_FOLDER``.

                This method will call a ``set_file_path(file_path)`` 
                on the specified drbf if ``file_path`` isn't a ``None``.

                You can change drbf ``file_path`` with
                ``set_file_path`` method before importing
                file, so you don't need to specify it here.
        """
        # We need to fetch encrypted metadata
        if not drbf._erbf._initialized:
            await drbf._erbf.init()
        
        if not file_path:
            file_path = DEF_NO_FOLDER

        if file_path.is_file():
            file_path = file_path.parent

        drbf.set_file_path(file_path)
        
        pf = PreparedFile(
            dlb = self, 
            file = BytesIO(),
            filekey = drbf._filekey,
            filesize = drbf._size,
            filepath = drbf._file_path,
            filesalt = drbf._file_salt,
            metadata = drbf._erbf._metadata,
            imported = True
        )
        pf.set_file_id(drbf._id)
        pf.set_upload_time(drbf._upload_time)

        return await self._make_local_file(pf)
    
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

class DirectoryRoot:
    """
    Type used to specify that you want to
    access absolute local directory root.

    This class doesn't have any methods,
    please use it only for ``lbd.iterdir``
    """

class EncryptedLocalBoxDirectory:
    """
    Class that represents abstract tgbox directory. You
    can iterate over all files/folders in it, as well
    as load parent folder up to root.

    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box
        from tgbox.keys import make_basekey, Phrase
        
        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_local_box(basekey)
            dlbfi = await dlb.get_file(await dlb.get_last_file_id())
            
            # Load directory up to the root
            await dlbfi.directory.lload(full=True)

            print(dlbfi.directory)
            
            # Iterate over files/folders in this directory
            async for content in dlbfi.directory.iterdir():
                print(content) # May be file or another dir

        asyncio_run(main())
    """
    def __init__(self, tgbox_db: TgboxDB, part_id: bytes):
        """
        Arguments:
            tgbox_db (``TgboxDB``):
                Tgbox Database.

            part_id (``bytes``):
                Path's part ID. You can fetch it from
                the ``PATH_PARTS`` table in ``TgboxDB``.
        """
        self._initialized = False
        self._tgbox_db = tgbox_db
        self._lb = EncryptedLocalBox(self._tgbox_db)
        
        self._part = None
        self._part_id = part_id
        self._parent_part_id = None

        self._parts = [self]
        self._floaded = False

    def __hash__(self) -> int:
        x = tuple(i.part for i in self._parts)
        # Without 22 hash of list will be equal to object's
        return hash((x, 22))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __str__(self) -> str:
        """Will return path for current loaded parts"""
        if isinstance(self._lb, DecryptedLocalBox):
            return str(Path(*[i.part.decode() for i in self._parts]))
        else:
            return self.__repr__()

    def __repr__(self) -> str:
        c = 'ELBD' if 'Encrypted' in self.__class__.__name__ else 'DLBD'
        return f'{c}[{self.part.decode() if c == "DLBD" else self.part}]'
    
    def __getitem__(self, _slice: slice):
        return self.parts[_slice]

    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().') 

    @property
    def initialized(self) -> bool:
        """
        Returns ``True`` if you 
        already called ``.init()``
        """
        return self._initialized
    
    @property
    def part(self) -> Union[bytes, None]:
        """
        Returns ``None`` if you didn't called
        the ``.init()`` method, encrypted path part
        if you're in ``EncryptedLocalBoxDirectory``,
        and decrypted if ``DecryptedLocalBoxDirectory``.
        """
        return self._part
    
    @property
    def part_id(self) -> bytes:
        """Returns path part ID"""
        return self._part_id

    @property
    def parent_part_id(self) -> Union[bytes, None]:
        """
        Returns ``None`` if you didn't called the ``.init()`` 
        method, parent path part ID otherwise.
        """
        return self._parent_part_id
    
    @property
    def parts(self) -> list:
        """Will return loaded path parts."""
        return self._parts
    
    @property
    def floaded(self) -> bool:
        """Will return ``True`` if path was fully loaded"""
        return self._floaded

    async def init(self) -> 'EncryptedLocalBoxDirectory':
        """Will fetch required data from the database."""
        folder_row = await self._tgbox_db.PATH_PARTS.select_once((
            'SELECT * FROM PATH_PARTS WHERE PART_ID=?', 
            (self._part_id,)
        ))
        self._part = folder_row[0]
        self._part_id = folder_row[1]
        self._parent_part_id = folder_row[2]

        if not self._lb.initialized:
            await self._lb.init()

        self._initialized = True
        return self

    async def lload(self, full: Optional[bool] = False):
        """
        Will load and return one path part 
        from the left side (previous) or 
        return ``None`` if there is nothing left.
        
        Arguments:
            full (``bool``, optional):
                If ``full`` is ``True``, will load all parts
                from the left side and return ``None``.
        """
        self.__raise_initialized()

        for _ in range(256**8 if full else 1):
            previous_part = await self._tgbox_db.PATH_PARTS.select_once((
                'SELECT PARENT_PART_ID FROM PATH_PARTS WHERE PART_ID=?', 
                (self.parts[0].part_id,)
            ))
            if not previous_part[0]:
                self._floaded = True
                return
            
            if isinstance(self._lb, DecryptedLocalBox):
                previous_part = await EncryptedLocalBoxDirectory(
                    self._tgbox_db, previous_part[0]).decrypt(self._lb._mainkey)
            else:
                previous_part = await EncryptedLocalBoxDirectory(
                    self._tgbox_db, previous_part[0]).init()
             
            self.parts.insert(0, previous_part)
        
        return previous_part
    
    async def iterdir(
        self, 
        ignore_dirs: bool=False, 
        ignore_files: bool=False, 
        cache_preview: bool=True,
        ppid: Optional[Union[bytes, DirectoryRoot]] = None) -> Union[
            'EncryptedLocalBoxFile',
            'DecryptedLocalBoxFile',
            'EncryptedLocalBoxDirectory',
            'DecryptedLocalBoxDirectory'
        ]:
        """
        Iterate over all files/folders
        in this abstract directory.
        
        Arguments:
            ignore_dirs (``bool``, optional):
                Return abstract folders from this
                directory as LocalBoxDirectory or
                not. If ``False`` will return only
                LocalBoxFile objects.

            ignore_files (``bool``, optional):
                Will return LocalBoxFile if ``False``.

            cache_preview (``bool``, optional):
                Cache preview in class or not. 
                ``True`` by default.

            ppid (``bytes``, ``DirectoryRoot``):
                Path PartID to iterate in. Will iterate over
                absolute LocalBox directory root if it's 
                ``DirectoryRoot``. Will use ``self.part_id``
                if not specified (by default).
        """
        assert not all((ignore_files, ignore_dirs)), 'Specify at least one'

        if isinstance(ppid, DirectoryRoot) or ppid is DirectoryRoot:
            part_id = None
        elif ppid:
            part_id = ppid
        else:
            part_id = self._part_id

        if not ignore_dirs:
            folders = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT * FROM PATH_PARTS WHERE PARENT_PART_ID IS ?', 
                (part_id,)
            ))
            async for folder_row in folders:
                if isinstance(self._lb, DecryptedLocalBox):
                    yield await EncryptedLocalBoxDirectory(self._tgbox_db,
                        folder_row[1]).decrypt(self._lb._mainkey)
                else:
                    yield await EncryptedLocalBoxDirectory(self._tgbox_db,
                        folder_row[1]).init()
        
        if not ignore_files:
            files = await self._tgbox_db.FILES.execute((
                'SELECT * FROM FILES WHERE PPATH_HEAD IS ?', 
                (part_id,)
            ))
            async for file_row in files:
                yield await self._lb.get_file(
                    file_row[0], cache_preview=cache_preview)

    async def delete(self) -> None: 
        """
        Will delete this folder with all files from your LocalBox.
        All files will stay in ``RemoteBox``, so you can restore
        all your folders by importing files.
        """
        await self._tgbox_db.FILES.execute(
            ('DELETE FROM FILES WHERE PPATH_HEAD=?',(self._part_id,))
        )
        await self._tgbox_db.PATH_PARTS.execute(
            ('DELETE FROM PATH_PARTS WHERE PART_ID=?',(self._part_id,))
        )
    async def decrypt(self, key: Union[BaseKey, MainKey]):
        """Decrypt self and return ``DecryptedLocalBoxDirectory``"""
        if not self._initialized: await self.init()
        return DecryptedLocalBoxDirectory(self, key)

class DecryptedLocalBoxDirectory(EncryptedLocalBoxDirectory):
    def __init__(
            self, elbd: EncryptedLocalBoxDirectory, 
            key: Union[BaseKey, MainKey]):
        """
        Arguments:
            elbd (``EncryptedLocalBoxDirectory``):
                Initialized ``EncryptedLocalBoxDirectory``.
            
            key (``BaseKey``, ``MainKey``):
                Decryption ``Key``.
        """
        super().__init__(elbd._tgbox_db, elbd._part_id)

        self._initialized = True
        self._elbd = elbd
        
        self._lb = DecryptedLocalBox(elbd._lb, key)
        self._part = AES(self._lb._mainkey).decrypt(elbd._part)

    @staticmethod
    def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxDirectory`` """
            """and cannot be used on ``DecryptedLocalBoxDirectory``."""
        )
    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxDirectory`` """
            """and cannot be used on ``DecryptedLocalBoxDirectory``."""
        )

class EncryptedLocalBoxFile:
    """
    This class represents an encrypted local file. On
    more low-level that's a wrapper around row of
    ``FILES`` table in Tgbox Database. Usually you
    will not use this in your code.

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box
        from tgbox.keys import make_basekey, Phrase
        
        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_local_box(basekey)
            
            elbf = await dlb.get_file(
                id = await dlb.get_last_file_id(), 
                decrypt = False 
            )
            print(elbf.file_salt.hex())
            print(elbf.box_salt.hex())

        asyncio_run(main())
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
        self._id = id
        self._tgbox_db = tgbox_db
        self._cache_preview = cache_preview
        
        self._initialized = False

        self._ppath_head, self._upload_time = None, None
        self._metadata, self._directory = None, None
        self._exported, self._efilekey = None, None
        self._updated_metadata = None

    def __hash__(self) -> int:
        return hash((self._id, 22))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def initialized(self) -> bool:
        """
        Returns ``True`` if you 
        already called ``.init()``
        """
        return self._initialized
    
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
    def directory(self) -> Union[
            EncryptedLocalBoxDirectory, 
            DecryptedLocalBoxDirectory, 
            None
        ]:
        """
        Returns ``None`` i you call it on 
        ``EncryptedLocalBoxFile`` that wasn't
        initialized, ``EncryptedLocalBoxDirectory``
        if on initialized or ``DecryptedLocalBoxDirectory``
        if you call it on ``DecryptedLocalBoxFile``
        """
        return self._directory

    @property
    def id(self) -> Union[int, None]:
        """
        Returns file ID or ``None`` 
        if file wasn't initialized
        """
        return self._id

    @property
    def upload_time(self) -> Union[bytes, int, None]:
        """
        Returns encrypted ``upload_time`` from
        ``EncryptedLocalBoxFile`` and decrypted
        from ``DecryptedLocalBoxFile``. ``None``
        if class wasn't initialized.
        """
        return self._upload_time

    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().') 
    
    async def init(self) -> 'EncryptedLocalBoxFile':
        """Will fetch and parse data from the Database."""
        
        file_row = list(await self._tgbox_db.FILES.select_once(
            sql_tuple = ('SELECT * FROM FILES WHERE ID=?', (self._id,))
        ))
        self._updated_metadata = file_row.pop()
        self._metadata = file_row.pop()
        self._efilekey = file_row.pop()
        self._ppath_head = file_row.pop()
        self._upload_time = file_row.pop()
        self._id = file_row.pop()

        self._directory = EncryptedLocalBoxDirectory(
            self._tgbox_db, self._ppath_head
        )
        await self._directory.init()

        self._exported = bool(self._efilekey)
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
        # Getting file row for PPATH_HEAD
        file_row = await self._tgbox_db.FILES.select_once(
            sql_tuple=('SELECT PPATH_HEAD FROM FILES WHERE ID=?',(self._id,))
        )
        # Removing requested file
        await self._tgbox_db.FILES.execute(
            ('DELETE FROM FILES WHERE ID=?',(self._id,))
        )
        try:
            pp_row = await self._tgbox_db.FILES.select_once(sql_tuple=(
                'SELECT ID FROM FILES WHERE PPATH_HEAD=?',(file_row[0],)
            ))
        # Only one file point to this path part (folder)
        except StopAsyncIteration:
            await self._tgbox_db.PATH_PARTS.execute((
                'DELETE FROM PATH_PARTS WHERE PART_ID=?',(file_row[0],)
            ))
    
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

class DecryptedLocalBoxFile(EncryptedLocalBoxFile):
    """
    This class represents an decrypted local file. 
    On more low-level that's a wrapper of ``FILES``
    table in Tgbox Database that decrypts row. 

    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box
        from tgbox.keys import make_basekey, Phrase
        
        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_local_box(basekey)
            lfid = dlb.get_last_file_id()
            dlbfi = await dlb.get_file(lfid)

            print(dlbfi.id, dlbfi.id, dlbfi.size)

        asyncio_run(main())
    """
    def __init__(
            self, elbf: EncryptedLocalBoxFile, 
            key: Union[FileKey, ImportKey, MainKey],
            cache_preview: bool=True):
        """
        Arguments:
            elbf (``EncryptedLocalBoxFile``):
                Encrypted local box file that
                you want to decrypt.

            key (``FileKey``, ``ImportKey``, ``MainKey``):
                Decryption key.

            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        if not elbf._initialized:
            raise NotInitializedError('You should init elbf firstly')
        
        self._initialized = True 

        self._elbf = elbf
        self._key = key
        self._tgbox_db = elbf._tgbox_db
        
        self._efilekey = elbf._efilekey
        
        self._id = elbf._id
        self._exported = elbf._exported
        self._ppath_head = elbf._ppath_head
        self._updated_metadata = elbf._updated_metadata

        if cache_preview is None:
            self._cache_preview = elbf._cache_preview
        else:
            self._cache_preview = cache_preview
        
        self._prefix = self._elbf._metadata[:len(PREFIX)]
        self._version_byte = self._elbf._metadata[
            len(PREFIX) : len(VERBYTE) + len(PREFIX)
        ]
        pattr_offset = len(PREFIX) + len(VERBYTE) + 3

        unpacked_metadata = PackedAttributes.unpack(
            self._elbf._metadata[pattr_offset:-16]
        )
        self._file_iv = self._elbf._metadata[-16:]
        self._file_salt = unpacked_metadata['file_salt']
        self._box_salt = unpacked_metadata['box_salt']

        if isinstance(key, (FileKey, ImportKey)):
            self._filekey = FileKey(key.key)
        elif isinstance(key, MainKey) and self._efilekey:
            self._filekey = FileKey(
                AES(self._key).decrypt(self._efilekey)
            )
        else:
            self._filekey = make_filekey(self._key, self._file_salt)
        
        if isinstance(key, MainKey):
            self._mainkey = key
        else:
            self._mainkey = None
        
        self._upload_time = AES(self._filekey).decrypt(elbf._upload_time)
        self._upload_time = bytes_to_int(self._upload_time)

        secret_metadata = AES(self._filekey).decrypt(
            unpacked_metadata['secret_metadata']
        )
        if len(secret_metadata) == len(unpacked_metadata['secret_metadata'])-16:
            raise AESError('Metadata wasn\'t decrypted correctly. Incorrect key?')
        
        secret_metadata = PackedAttributes.unpack(secret_metadata)
        
        self.__required_metadata = [
            'duration', 'file_size', 'file_name', 
            'cattrs', 'mime', 'efile_path', 'preview'
        ]
        for attr in self.__required_metadata:
            setattr(self, f'_{attr}', secret_metadata[attr])

        if not cache_preview:
            self._preview = b''

        self._size = bytes_to_int(self._file_size)
        del self._file_size

        self._duration = bytes_to_int(self._duration)
        self._cattrs = PackedAttributes.unpack(self._cattrs)
        self._mime = self._mime.decode()

        if self._mainkey and not self._efilekey:
            self._file_path = AES(self._mainkey).decrypt(
                secret_metadata['efile_path']
            )
            self._file_path = Path(self._file_path.decode())
        else:
            self._file_path = None

        for attr in self.__required_metadata:
            secret_metadata.pop(attr)

        self._residual_metadata = secret_metadata
        
        if self._mainkey:
            self._directory = DecryptedLocalBoxDirectory(
                self._elbf._directory, self._mainkey
            )
        else:
            self._directory = self._elbf._directory

        self._download_path = DOWNLOAD_PATH 
        
        if self._elbf._updated_metadata:
            updates = AES(self._filekey).decrypt(
                self._elbf._updated_metadata 
            )
            updates = PackedAttributes.unpack(updates)

            for k,v in tuple(updates.items()):
                if k in self.__required_metadata:
                    if k == 'cattrs':
                        setattr(self, f'_{k}', PackedAttributes.unpack(v))

                    elif k == 'efile_path':
                        if self._mainkey and not self._efilekey:
                            self._file_path = AES(self._mainkey).decrypt(v)
                            self._file_path = Path(self._file_path.decode())
                        else:
                            self._file_path = None
                    else:
                        setattr(self, f'_{k}', v)
                else:
                    self._residual_metadata[k] = v

        self._elbf._initialized = False
        self._elbf._metadata = None # To save RAM
        self._elbf._updated_metadata = None
    
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
    def residual_metadata(self) -> dict:
        """
        Will return metadata that left after
        parsing secret_metadata. This can be
        useful in future, when lower version
        will read file of a higher version.
        """
        return self._residual_metadata

    @property
    def file_path(self) -> Path:
        """Returns file path."""
        return self._file_path

    @property 
    def file_name(self) -> bytes:
        """Returns file name."""
        return self._file_name

    @property
    def file_iv(self) -> bytes:
        """Returns file IV."""
        return self._file_iv

    @property
    def file_salt(self) -> bytes:
        """Returns FileSalt."""
        return self._file_salt

    @property
    def preview(self) -> Union[bytes, None]:
        """
        Returns preview bytes or ``None``
        if ``cache_preview`` is ``False``.
        """
        return self._preview

    @property
    def size(self) -> int:
        """Returns file size (no metadata included)."""
        return self._size
    
    @property
    def duration(self) -> int:
        """Returns media file duration."""
        return self._duration
    
    @property
    def cattrs(self) -> Union[bytes, None]:
        """Returns file Custom Attributes"""
        return self._cattrs

    @property
    def mime(self) -> Union[bytes, None]:
        """Returns mime type of the file"""
        return self._mime

    @property
    def download_path(self) -> Path:
        """Returns current download path"""
        return self._download_path
    
    def set_download_path(self, path: Path):
        """Will set download path to specified."""
        self._download_path = path
    
    async def refresh_metadata(
            self, drb: Optional[DecryptedRemoteBox] = None, 
            _updated_metadata: Optional[bytes] = None
        ):
        """
        This method will refresh local UPDATED_METADATA from
        the remote box file. You should call it after
        every ``DecryptedRemoteBoxFile.update_metadata``
        await, or specify ``DecryptedLocalBox`` when
        awaiting ``update_metadata`` as ``dlb`` kwarg.

        Arguments:
            drb (``DecryptedRemoteBox``, optional):
                ``DecryptedRemoteBox`` associated with 
                this ``DecryptedLocalBox``.

            _updated_metadata (``bytes``, optional):
                Updated metadata by itself. This is for
                internal use, specify only ``drb``.

        You should specify at least one argument.
        """
        assert any((drb, _updated_metadata)), 'Specify at least one'

        if not _updated_metadata:
            drbf = await drb.get_file(self._id)
            _updated_metadata = drbf._message.message

        await self._tgbox_db.FILES.execute((
            'UPDATE FILES SET UPDATED_METADATA=? WHERE ID=?',
            (_updated_metadata, self._id)
        )) 

    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this file. You should
        use this method if you want to share your
        ``DecryptedLocalBoxFile`` with other people.
        
        Arguments:
            reqkey (``RequestKey``, optional):
                Other's ``RequestKey``. If isn't specified
                returns ``ShareKey`` of this file without
                encryption, so ANYONE with this key can
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
class PreparedFile:
    """
    This dataclass store data needed for upload 
    by ``DecryptedRemoteBox.push_file`` in future. 

    Usually it's only for internal use.
    """
    dlb: DecryptedLocalBox
    file: BinaryIO
    filekey: FileKey
    filesize: int
    filepath: Path
    filesalt: bytes
    metadata: bytes
    imported: bool
    
    def set_file_id(self, id: int):
        """You should set ID after pushing to remote"""
        self.file_id = id

    def set_upload_time(self, upload_time: int):
        """You should set time after pushing to remote"""
        self.upload_time = upload_time

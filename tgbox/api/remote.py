"""Module with API functions and classes for RemoteBox."""

import logging

from typing import (
    BinaryIO, Union, NoReturn, Callable,
    AsyncGenerator, List, Dict, Optional
)
from pathlib import Path
from asyncio import gather, sleep

from os import PathLike
from traceback import format_exc

from base64 import (
    urlsafe_b64encode,
    urlsafe_b64decode
)
from asyncio import iscoroutinefunction
from hmac import HMAC, compare_digest as hmac_compare_digest

from telethon.utils import resolve_id
from telethon.tl.custom.file import File

from telethon.tl.functions.messages import (
    EditChatAboutRequest, SearchRequest
)
from telethon.errors import (
    ChatAdminRequiredError,
    MediaCaptionTooLongError,
    MessageNotModifiedError,
    AuthKeyUnregisteredError,
    MessageIdInvalidError
)
from telethon.tl.functions.channels import (
    CreateChannelRequest, EditPhotoRequest,
    GetFullChannelRequest, DeleteChannelRequest
)
from telethon.tl.types import (
    Channel, Message, PeerChannel,
    InputMessagesFilterDocument
)
from ..crypto import (
    AESwState as AES,
    BoxSalt, FileSalt, IV
)
from ..keys import (
    make_mainkey, make_sharekey, MainKey, ShareKey,
    ImportKey, FileKey, BaseKey, HMACKey, make_filekey,
    make_requestkey, RequestKey, DirectoryKey, make_dirkey,
    make_hmackey
)
from ..defaults import (
    VERBYTE, BOX_IMAGE_PATH, DEF_TGBOX_NAME,
    Limits, PREFIX, DEF_UNK_FOLDER, UploadLimits,
    REMOTEBOX_PREFIX, DEF_NO_FOLDER, DOWNLOAD_PATH
)
from ..fastelethon import upload_file, download_file

from ..errors import (
    NotInitializedError, RemoteBoxInaccessible,
    NotEnoughRights, NotATgboxFile, IncorrectKey,
    LimitExceeded, NotImported, AESError, RemoteFileNotFound,
    NoPlaceLeftForMetadata, SessionUnregistered, InvalidFile
)
from ..tools import (
    int_to_bytes, bytes_to_int, SearchFilter, OpenPretender,
    pad_request_size, PackedAttributes, prbg, anext,
    make_safe_file_path, make_general_path, ppart_id_generator
)
from .utils import (
    TelegramClient, RemoteBoxDefaults,
    DefaultsTableWrapper, search_generator
)
__all__ = [
    'make_remotebox',
    'get_remotebox',
    'EncryptedRemoteBox',
    'DecryptedRemoteBox',
    'EncryptedRemoteBoxFile',
    'DecryptedRemoteBoxFile',
]
logger = logging.getLogger(__name__)

async def make_remotebox(
        tc: TelegramClient,
        box_name: Optional[str] = DEF_TGBOX_NAME,
        rb_prefix: Optional[str] = REMOTEBOX_PREFIX,
        box_image: Optional[Union[PathLike, str]] = BOX_IMAGE_PATH,
        box_salt: Optional[BoxSalt] = None) -> 'EncryptedRemoteBox':
    """
    Function used for making ``RemoteBox``.

    Arguments:
        tc (``TelegramClient``):
            Account to make private Telegram channel.
            You must be signed in via ``log_in()``.

        box_name (``str``, optional):
            Name of your Local and Remote boxes.
            ``defaults.DEF_TGBOX_NAME`` by default.

        rb_prefix (``str``, optional):
            Prefix of your RemoteBox.
            ``defaults.REMOTEBOX_PREFIX`` by default.

        box_image (``PathLike``, optional):
            ``PathLike`` to image that will be used as
            ``Channel`` photo of your ``RemoteBox``.

            Can be setted to ``None`` if you don't
            want to set ``Channel`` photo.

        box_salt (``BoxSalt``, optional):
            Random 32 bytes. Will be used in ``MainKey``
            creation. Default is ``BoxSalt.generate()``.
    """
    if box_salt and len(box_salt) != 32:
        raise ValueError('BoxSalt bytelength != 32')

    box_salt = (box_salt if box_salt else BoxSalt.generate()).salt
    box_salt = urlsafe_b64encode(box_salt).decode()

    channel_name = rb_prefix + box_name

    logger.info(f'Making RemoteBox {channel_name} ({box_salt[:12]}...)')

    channel = (await tc(CreateChannelRequest(
        channel_name, '', megagroup=False))).chats[0]

    if box_image:
        box_image = await tc.upload_file(open(box_image,'rb'))
        await tc(EditPhotoRequest(channel, box_image))

    await tc(EditChatAboutRequest(channel, box_salt))
    return EncryptedRemoteBox(channel, tc)

async def get_remotebox(
        dlb: Optional['DecryptedLocalBox'] = None,
        tc: Optional['TelegramClient'] = None,
        entity: Optional[Union[int, str, PeerChannel]] = None,
        proxy: Optional[Union[tuple, list, dict]] = None)\
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

        proxy (tuple, list, dict, optional):
            An iterable consisting of the proxy info. If connection
            is one of MTProxy, then it should contain MTProxy credentials:
            ('hostname', port, 'secret'). Otherwise, it’s meant to store
            function parameters for PySocks, like (type, 'hostname', port).
            See https://github.com/Anorov/PySocks#usage-1 for more info.
    """
    if tc:
        account = tc

    elif tc and not entity:
        raise ValueError('entity must be specified with tc')
    else:
        account = TelegramClient(
            session=dlb._session,
            api_id=dlb._api_id,
            api_hash=dlb._api_hash,
            proxy=proxy
        )
        await account.connect()

    if dlb:
        logger.info(
            f'''Getting RemoteBox ID{dlb._box_channel_id} '''
            f'''with the {dlb._tgbox_db._db_path} LocalBox'''
        )
    else:
        logger.info(f'Getting RemoteBox ({entity}) with TelegramClient')
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
        logger.debug('DLB is NOT specified, return EncryptedRemoteBox')
        return EncryptedRemoteBox(channel_entity, account)
    else:
        logger.debug('DLB is specified, return DecryptedRemoteBox')
        return await EncryptedRemoteBox(
            channel_entity, account).decrypt(dlb=dlb)

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
            make_localbox,
            make_remotebox
        )
        from getpass import getpass
        from asyncio import run as asyncio_run

        PHONE_NUMBER = '+10000000000' # Your phone number
        API_ID = 1234567 # Your own API_ID: my.telegram.org
        API_HASH = '00000000000000000000000000000000' # Your own API_HASH

        async def main():
            # Connect and sign-in to Telegram
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
            erb = await make_remotebox(tc)

        asyncio_run(main())
    """
    def __init__(self,
            box_channel: Channel,
            tc: TelegramClient,
            defaults: Optional[Union[RemoteBoxDefaults,
                DefaultsTableWrapper]] = None):
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

            defaults (``DefaultsTableWrapper``, ``RemoteBoxDefaults``):
                Class with a default values/constants we will use.
        """
        self._tc = tc

        self._box_channel = box_channel
        self._box_channel_id = resolve_id(box_channel.id)[0]

        # We can't use await in __init__, so
        # you should await get_box_salt firstly.
        self._box_salt = None
        # Similar to box_salt, await get_box_description.
        self._description = None
        # Similar to box_salt, await get_box_name.
        self._box_name = None

        self._is_encrypted = True

        if defaults:
            logger.debug('ERB: Found custom defaults, will try to use it')
            self._defaults = defaults
        else:
            logger.debug('ERB: Custom defaults is not present')

            self._defaults = RemoteBoxDefaults(
                METADATA_MAX = Limits.METADATA_MAX,
                FILE_PATH_MAX = Limits.FILE_PATH_MAX,
                DEF_UNK_FOLDER = DEF_UNK_FOLDER,
                DEF_NO_FOLDER = DEF_NO_FOLDER,
                DOWNLOAD_PATH = DOWNLOAD_PATH
            )

    def __repr__(self) -> str:
        return f'<class {self.__class__.__name__}({self._box_channel}, {self._tc}, {repr(self._defaults)})>'

    def __str__(self) -> str:
        box_salt = None if not self._box_salt else urlsafe_b64encode(self._box_salt.salt).decode()
        return (
            f'''<class {self.__class__.__name__}({self._box_channel}, {self._tc}, {repr(self._defaults)})> '''
            f'''# {self._box_name=}, {box_salt=}'''
        )
    def __hash__(self) -> int:
        # Without 22 hash of int wil be equal to object's
        return hash((self._box_channel_id, 22))

    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__),
            self._box_channel_id == other.box_channel_id
        ))
    @property
    def defaults(self) -> Union[DefaultsTableWrapper, RemoteBoxDefaults]:
        """
        Will return ``DefaultsTableWrapper`` if
        ``dlb`` was specified or ``RemoteBoxDefaults``
        with arguments from the ``defaults`` module if wasn't.
        """
        return self._defaults

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

    @property
    def is_encrypted(self) -> bool:
        """
        Will return ``True`` if this is an *Encrypted*
        class, ``False`` if *Decrypted*
        """
        return self._is_encrypted

    async def get_last_file_id(self) -> int:
        """Returns last channel file id. If nothing found returns 0"""
        async for msg in self._tc.iter_messages(self._box_channel):
            if not msg:
                continue
            if msg.document:
                return msg.id
        return 0

    async def get_files_total(self) -> int:
        """Returns a total number of files in this RemoteBox"""

        search = await self._tc(SearchRequest(
            peer = self._box_channel,
            filter = InputMessagesFilterDocument(),

            q = '',
            min_date = None,
            max_date = None,

            offset_id = 0,
            add_offset = 0,
            limit = 0,
            max_id = 0,
            min_id = 0,
            hash = 0
        ))
        return search.count

    async def get_box_salt(self, force: Optional[bool] = False) -> BoxSalt:
        """
        Returns ``BoxSalt``. Will be cached after first
        method call. If ``force`` specified, will make
        request & update ``box_salt`` & ``description``
        """
        if force or not self._box_salt:
            full_rq = await self._tc(GetFullChannelRequest(channel=self._box_channel))

            # Started from v1.5 users now can place additional Box
            # description in format "User description @ <BOX_SALT>"
            desc_data = full_rq.full_chat.about.split('@')

            self._box_salt = BoxSalt(urlsafe_b64decode(desc_data[-1]))

            if len(desc_data) > 1:
                self._description = '@'.join(desc_data[:-1]).strip()
            else:
                self._description = None # Remove if cached

        return self._box_salt

    async def get_box_name(self):
        """
        Returns name of ``RemoteBox``.
        Will be cached after first method call.
        """
        if not self._box_name:
            entity = await self._tc.get_entity(self._box_channel)
            self._box_name = entity.title.split(': ', 1)[-1]
        return self._box_name

    async def get_box_description(self, force: Optional[bool] = False):
        """
        Returns *Box* description if presented. If ``force``
        specified, will make request & update ``box_salt``
        and ``description``.
        """
        if force or not self._description:
            await self.get_box_salt(force=True)
        return self._description

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
            decrypt: Optional[bool] = None,
            ignore_errors: bool=True,
            return_imported_as_erbf: bool=False,
            cache_preview: bool=True,
            erase_encrypted_metadata: bool=True) -> Union[
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
                this file (tip: you need to import it with ``dlb.import_file``).

            decrypt (``bool``, optional):
                Returns ``DecryptedRemoteBoxFile`` if ``True``,
                ``EncryptedRemoteBoxFile`` otherwise. If
                ``None``, will be determined by class.

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

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedRemoteBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        logger.info(f'Getting file ID{id} from the RemoteBox ID{self._box_channel_id}')

        if hasattr(self, '_mainkey') and not key:
            logger.debug('self have _mainkey, will try to return DecryptedRemoteBoxFile')
            key = self._mainkey # pylint: disable=no-member

        if hasattr(self, '_dlb'):
            logger.debug('self have _dlb, will try to return DecryptedRemoteBoxFile')
            dlb = self._dlb # pylint: disable=no-member

        file_iter = self.files(
            key, dlb=dlb, decrypt=decrypt,
            ids=id, cache_preview=cache_preview,
            return_imported_as_erbf=return_imported_as_erbf,
            ignore_errors=ignore_errors,
            erase_encrypted_metadata=erase_encrypted_metadata)
        try:
            return await anext(file_iter)
        # If there is no file by ``id``.
        except StopAsyncIteration:
            return None

    async def files(
            self, key: Optional[Union[MainKey, FileKey]] = None,
            drb: Optional['DecryptedRemoteBox'] = None,
            dlb: Optional['DecryptedLocalBox'] = None,
            *,
            ignore_errors: bool=True,
            return_imported_as_erbf: bool=False,
            limit: Optional[int] = None,
            offset_id: int=0,
            max_id: int=0,
            min_id: int=0,
            add_offset: int=0,
            search: Optional[str] = None,
            from_user: Optional[Union[str, int]] = None,
            wait_time: Optional[float] = None,
            ids: Optional[Union[int, List[int]]] = None,
            reverse: bool=False,
            decrypt: Optional[bool] = None,
            timeout: int=15,
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
            - You can ignore ``key`` and ``drb`` if you call\
            this method on ``DecryptedRemoteBox``.

        Arguments:
            key (``MainKey``, ``FileKey``, optional):
                Will be used to decrypt ``EncryptedRemoteBoxFile``.

            drb (``DecryptedRemoteBox``):
                Decrypted RemoteBox. Will be used to decrypt
                ``EncryptedRemoteBoxFile``

            dlb (``DecryptedLocalBox``, optional):
                If file in your ``RemoteBox`` was imported from
                other ``RemoteBox``, then you can't decrypt it with
                specified mainkey, but if you already imported it
                to your LocalBox, then you can specify ``dlb``
                and we will use ``FILEKEY`` from the Database.

                If ``decrypt`` specified but there is no ``key``,
                then we will try to use mainkey from this dlb.

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
                order (from newest to oldest, instead of the default oldest
                to newest). This also means that the meaning of ``offset_id``
                parameter is reversed, although ``offset_id`` still be exclusive.
                ``min_id`` becomes equivalent to ``offset_id`` instead of being ``max_id``
                as well since files are returned in ascending order.

            timeout (``int``, optional):
                How many seconds generator will sleep at every 1000 file.
                By default it's 15 seconds. Don't use too low timeouts,
                you will receive FloodWaitError otherwise (TGBOX).

            decrypt (``bool``, optional):
                Returns ``DecryptedRemoteBoxFile`` if ``True``,
                ``EncryptedRemoteBoxFile`` otherwise. If
                ``None``, will be determined by class.

            cache_preview (``bool``, optional):
                Cache preview in yielded by generator
                RemoteBoxFiles or not. ``True`` by default.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedRemoteBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        logger.info(f'*RemoteBox.files generator started, ids={ids}')

        # The *RemoteBox.files(...) by default will return files
        # in the ascending order (from oldest to newest) as well
        # as in *LocalBox.files(...), but Telethon's default
        # iter_messages behaviour is opposite (from newest
        # to oldest) so here we flip `reverse` only for this.
        reverse = (not reverse)

        # ============================================================ #

        if key:
            logger.debug('Custom key specified, will try to use it to decrypt files')

        elif not key and dlb:
            logger.debug('We will take a MainKey from DecryptedLocalBox')
            key = dlb._mainkey

        if not drb and isinstance(self, DecryptedRemoteBox):
            logger.debug('DecryptedRemoteBox is self')
            drb = self

        # ============================================================ #

        erb = self._erb if isinstance(self, DecryptedRemoteBox) else self

        # ============================================================ #

        if decrypt is None and isinstance(self, DecryptedRemoteBox):
            decrypt = True

        elif decrypt is None and isinstance(self, EncryptedRemoteBox):
            decrypt = False

        if decrypt and not any((dlb, drb, key)):
            raise ValueError('At least one of dlb, drb or key must be specified.')

        # ============================================================ #

        it_messages = self._tc.iter_messages(
            self._box_channel, limit=limit, offset_id=offset_id,
            max_id=max_id, min_id=min_id, add_offset=add_offset,
            search=search, from_user=from_user, wait_time=wait_time,
            ids=ids, reverse=reverse
        )
        async def rbf_wrapper(m):
            if not m or not m.document:
                return

            if not decrypt:
                logger.debug(
                    '''Decryption is disabled, will try to '''
                    '''yield EncryptedRemoteBoxFile''')

                try:
                    return await EncryptedRemoteBoxFile(
                        id=None, erb=erb, message_document=m,
                        cache_preview=cache_preview,
                        defaults=self._defaults).init()

                except NotATgboxFile:
                    logger.debug(
                       f'''Document: {m.file.name[:12]}...(ID{m.id}) '''
                        '''is not a TGBOX file, skipping.'''
                    )
                    return

            logger.debug(
                '''Decryption is enabled, will try to '''
                '''yield DecryptedRemoteBoxFile''')
            try:
                erbf = EncryptedRemoteBoxFile(
                    id=None, erb=erb, message_document=m,
                    cache_preview=cache_preview,
                    defaults=self._defaults
                )
                return await erbf.decrypt(key=key, drb=drb,
                    erase_encrypted_metadata=erase_encrypted_metadata)

            except Exception as e: # In case of imported file
                logger.debug(
                    '''Failed to decrypt EncryptedRemoteBoxFile '''
                   f'''(ID{m.id}), it seems that file is imported/'''
                   f'''non-TGBOX [{e}]'''
                )
                if return_imported_as_erbf and not dlb:
                    logger.debug(
                        '''return_imported_as_erbf is True & DLB '''
                        '''is not specified, so will return ERBF''')
                    try:
                        return await EncryptedRemoteBoxFile(
                            id=None, erb=erb, message_document=m,
                            cache_preview=cache_preview,
                            defaults=self._defaults).init()

                    except NotATgboxFile:
                        logger.debug(
                           f'''Document: {m.file.name[:12]}...(ID{m.id}) '''
                            '''is not a TGBOX file, skipping.'''
                        )
                        return

                elif ignore_errors and not dlb:
                    logger.debug(
                        '''return_imported_as_erbf is False & DLB '''
                        '''is not specified, ignore_errors is True '''
                        '''so we will continue iteration for other.'''
                    )
                    return

                elif not ignore_errors and not dlb:
                    raise IncorrectKey(
                        'File is imported. Try to specify dlb?') from None

                elif dlb:
                    logger.debug('DLB is specified, will try to fetch FileKey from it.')
                    # We try to fetch FileKey of imported file from DLB.
                    dlb_file = await dlb.get_file(m.id, cache_preview=False)

                    # If we haven't imported this file to DLB
                    if not dlb_file:
                        if return_imported_as_erbf:
                            try:
                                logger.debug(
                                   f'''DLB is specified, but FileKey to {m.id} is not '''
                                    '''present in it. return_imported_as_erbf is True, '''
                                    '''so we will return ERBF.'''
                                )
                                return await EncryptedRemoteBoxFile(
                                    id=None, erb=erb, message_document=m,
                                    cache_preview=cache_preview,
                                    defaults=self._defaults).init()

                            except NotATgboxFile:
                                logger.debug(
                                   f'''Document: {m.file.name[:12]}...(ID{m.id}) '''
                                    '''is not a TGBOX file, skipping.'''
                                )
                                return

                        elif ignore_errors:
                            logger.debug(
                               f'''DLB is specified, but FileKey to ID{m.id} is not '''
                                '''present in it. return_imported_as_erbf is False, '''
                                '''so we will skip it and continue iteration.'''
                            )
                            return
                        else:
                            raise NotImported(
                                """You don\'t have FileKey for this file. """
                                """Set to True ``return_imported_as_erbf``?"""
                            ) from None
                    else:
                        # We already imported file, so DLB contains a FileKey

                        erbf = EncryptedRemoteBoxFile(
                            id=None, erb=erb, message_document=m,
                            cache_preview=cache_preview,
                            defaults=self._defaults
                        )
                        return await erbf.decrypt(
                            key=dlb_file._filekey, drb=drb,
                            erase_encrypted_metadata=erase_encrypted_metadata)

        processed_messages = 0
        while True:
            # Sleep `timeout` seconds every 1000 files
            if processed_messages and processed_messages % 1000 == 0:
                logger.debug(f'Sleep {timeout=} seconds...')
                await sleep(timeout)

            logger.debug('Receiving the new chunk of messages...')

            messages_chunk = []
            for _ in range(100):
                try:
                    messages_chunk.append(rbf_wrapper(await anext(it_messages)))
                except StopAsyncIteration:
                    break

            processed_messages += len(messages_chunk)
            logger.debug(f'Chunk length = {len(messages_chunk)}')

            if not messages_chunk:
                break

            for drbf in (drbfiles := await gather(*messages_chunk)):
                if drbf: yield drbf

    async def search_file(
            self,
            sf: SearchFilter,
            mainkey: Optional[MainKey] = None,
            dlb: Optional['DecryptedLocalBox'] = None,
            cache_preview: bool=True,
            return_imported_as_erbf: bool=False,
            reverse: bool=False) -> AsyncGenerator[
                Union[
                    'EncryptedRemoteBoxFile',
                    'DecryptedRemoteBoxFile'
                ], None]:
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

            cache_preview (``bytes``, optional):
                Will cache preview in file object if ``True``.

            return_imported_as_erbf (``bool``, optional):
                If specified, will yield files that generator can't
                decrypt (imported) as ``EncryptedRemoteBoxFile``.

            reverse (``bool``, optional):
                If set to ``True``, the remote files will be
                returned in reverse order (from newest to
                oldest, instead of the default oldest to newest).

        .. note::
            - If ``dlb`` and ``mainkey`` not specified, then method\
            will search only for ``EncryptedRemoteBoxFile``.
            - You may ignore this kwargs if you call this\
            method on ``DecryptedRemoteBox`` class.
        """
        logger.info(f'Searching for files with {sf}')

        if hasattr(self, '_mainkey'):
            mainkey = self._mainkey

        if hasattr(self, '_dlb'):
            dlb = self._dlb

        min_id = sf.in_filters['min_id'][-1] if sf.in_filters['min_id'] else 0
        max_id = sf.in_filters['max_id'][-1] if sf.in_filters['max_id'] else 0
        ids = sf.in_filters['id'][-1] if sf.in_filters['id'] else None

        it_messages = self.files(
            key=mainkey,
            dlb=dlb,
            ids=ids,
            min_id=min_id,
            max_id=max_id,
            reverse=reverse,
            cache_preview=cache_preview,
            return_imported_as_erbf = return_imported_as_erbf
        )
        sgen = search_generator(
            sf, lb=dlb,
            it_messages=it_messages,
            cache_preview=cache_preview
        )
        async for file in sgen:
            yield file

    async def _push_file(
            self, pf: 'PreparedFile',
            progress_callback: Optional[Callable[[int, int], None]] = None,
            message_to_edit: Optional[Message] = None,
            use_slow_upload: Optional[bool] = False) -> 'DecryptedRemoteBoxFile':
        """
        Uploads ``PreparedFile`` to the ``RemoteBox``
        or updates already uploaded file in ``RemoteBox``.

        Arguments:
            pf (``PreparedFile``):
                PreparedFile to upload. You should recieve
                it via ``DecryptedLocalBox.prepare_file``.

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters:
                (downloaded_bytes, total).

            message_to_edit (``Message``, optional):
                If specified, will update existing ``RemoteBox``
                (edit) file instead of uploading new.

            use_slow_upload (``bool``, optional):
                Will use default upload function from the Telethon
                library instead of function from `fastelethon.py`.
                Use this if you have problems with upload.
        """
        if message_to_edit:
            logger.info(
                f'''Updating {message_to_edit.id=} with {pf.file=}'''
                f'''on RemoteBox ID{pf.dlb._box_channel_id}...''')
        else:
            logger.info(f'Pushing {pf.file=} to RemoteBox ID{pf.dlb._box_channel_id}...')

        me = await self._tc.get_me()

        if me.premium and pf.filesize > UploadLimits.PREMIUM:
            raise LimitExceeded(
                f'''Max allowed filesize for you is {UploadLimits.PREMIUM} '''
                f'''bytes, your file is {pf.filesize} bytes in size.'''
            )
        if not me.premium and pf.filesize > UploadLimits.DEFAULT:
            raise LimitExceeded(
                f'''Max allowed filesize for you is {UploadLimits.DEFAULT} '''
                f'''bytes, your file is {pf.filesize} bytes in size.'''
            )
        # Last 16 bytes of metadata is File IV
        aes_state = AES(pf.filekey, pf.metadata[-16:])
        # The hmac_state will be used to make a HMAC of File
        hmac_state = HMAC(pf.hmackey.key, digestmod='sha256')

        oe = OpenPretender(pf.file, aes_state, hmac_state, pf.filesize)
        oe.concat_metadata(pf.metadata)
        try:
            assert not use_slow_upload, 'use_slow_upload enabled'

            # Here we will use fast upload function
            ifile = await upload_file(
                self._tc, oe,
                file_name=urlsafe_b64encode(pf.filesalt.salt).decode(),
                part_size_kb=512, file_size=pf.filesize,
                progress_callback=progress_callback
            )
        except Exception as e:
            # If some error was found during uploading then it's
            # probably because of fast "upload_file(...)" from
            # the custom fastelethon module. We will try to
            # use the slow upload from the Telethon library
            if not isinstance(e, AssertionError): # We assert if use_slow_upload
                logger.warning(f'Fast upload FAILED, trying with SLOW!\n{format_exc()}')

            ifile = await self._tc.upload_file(
                oe, file_name=urlsafe_b64encode(pf.filesalt.salt).decode(),
                part_size_kb=512, file_size=pf.filesize,
                progress_callback=progress_callback)
        try:
            if message_to_edit:
                # This variable will be changed if Message has
                # Updated Metadata and if it was successfully
                # decrypted, re-encrypted and encoded.
                reenc_encoded_updated_metadata = None

                # Updated Encrypted Metadata
                if message_to_edit.message:
                    try:
                        decoded_ue_metadata = urlsafe_b64decode(
                            message_to_edit.message)
                    except Exception as e:
                        logger.info(
                            '''It seems that file you want to update have '''
                            '''Updated Metadata, but we can\'t decode. Updates '''
                            '''to Metadata will be ignored. {e}''')
                    else:
                        # urlsafe_b64decode was successfull, now we need
                        # to get FileKey to decrypt the Metadata updates
                        # and then re-encrypt them with a new FileKey
                        dlbf = await pf.dlb.get_file(message_to_edit.id)

                        try:
                            dec_updated_metadata = AES(dlbf._filekey).decrypt(
                                decoded_ue_metadata # Decrypt with original FileKey
                            )
                        except ValueError: # Invalid padding byte (AES Error)
                            logger.info(
                                '''It seems that file you want to update have '''
                                '''Updated Metadata, but we can\'t decrypt. '''
                                '''Updates to Metadata will be ignored. {e}''')
                        else:
                            reenc_updated_metadata = AES(pf.filekey).encrypt(
                                dec_updated_metadata # Re-encrypt with new FileKey
                            )
                            pf.set_updated_enc_metadata( # Add re-encrypted Metadata
                                reenc_updated_metadata   # to PreparedFile object so
                            )                            # we can re-use it in Local
                            reenc_encoded_updated_metadata = urlsafe_b64encode(
                                reenc_updated_metadata # Encode with Urlsafe b64
                            ).decode()

                file_message = await message_to_edit.edit(file=ifile,
                    text=reenc_encoded_updated_metadata)
            else:
                file_message = await self._tc.send_file(
                    self._box_channel, file=ifile,
                    silent=False, force_document=True,
                    caption = '<This caption must be removed>'
                )
                # We will set and remove caption only for
                # "Recent Actions" admin log. We can make
                # a quick synchronization with its help.
                await self._tc.edit_message(
                    entity = self._box_channel,
                    message = file_message, text = ''
                )
        except ChatAdminRequiredError:
            box_name = await self.get_box_name()

            if message_to_edit:
                raise NotEnoughRights(
                    '''You don\'t have enough privileges to edit'''
                   f'''another's files on remote {box_name}.''') from None
            else:
                raise NotEnoughRights(
                    '''You don\'t have enough privileges to upload '''
                   f'''files to remote {box_name}. Ask for it or '''
                    '''use this box as read only.'''
                ) from None

        pf.set_file_id(file_message.id)
        pf.set_upload_time(int(file_message.date.timestamp()))

        await pf.dlb._make_local_file(pf, update=bool(message_to_edit))

        erb = self._erb if isinstance(self, DecryptedRemoteBox) else self
        drb = self if isinstance(self, DecryptedRemoteBox) else None

        erbf = await EncryptedRemoteBoxFile(
            id=None, erb=erb, message_document=file_message,
            defaults=self._defaults).init()

        return await erbf.decrypt(key=pf.dlb._mainkey, drb=drb)

    async def push_file(
        self, pf: 'PreparedFile',
        progress_callback: Optional[Callable[[int, int], None]] = None,
        use_slow_upload: Optional[bool] = False) -> 'DecryptedRemoteBoxFile':
        """
        Uploads ``PreparedFile`` to the ``RemoteBox``.

        Arguments:
            pf (``PreparedFile``):
                PreparedFile to upload. You should recieve
                it via ``DecryptedLocalBox.prepare_file``.

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters:
                (downloaded_bytes, total).

            use_slow_upload (``bool``, optional):
                Will use default upload function from the Telethon
                library instead of function from `fastelethon.py`.
                Use this if you have problems with upload.
        """
        return await self._push_file(pf,
            progress_callback=progress_callback,
            use_slow_upload=use_slow_upload)

    async def update_file(self,
        rbf: Union['EncryptedRemoteBoxFile', 'DecryptedRemoteBoxFile'],
        pf: 'PreparedFile',
        progress_callback: Optional[Callable[[int, int], None]] = None,
        use_slow_upload: Optional[bool] = False) -> 'DecryptedRemoteBoxFile':
        """
        Updates already uploaded ``RemoteBox`` file.
        This will make a full reupload and ``Message`` edit.

        rbf (``EncryptedRemoteBoxFile``, ``DecryptedRemoteBoxFile``):
            The ``RemoteBox`` file to update. We will only take
            a ``Message`` object from it. The ``rbf`` **will NOT**
            be updated by itself, instead, new ``RemoteBox`` file
            object will be returned after update.

        pf (``PreparedFile``):
            ``PreparedFile`` to upload. You should recieve
            it via ``DecryptedLocalBox.prepare_file`` (set
            ``skip_fingerprint_check`` to ``True``).

        progress_callback (``Callable[[int, int], None]``, optional):
            A callback function accepting two parameters:
            (downloaded_bytes, total).

        use_slow_upload (``bool``, optional):
            Will use default upload function from the Telethon
            library instead of function from `fastelethon.py`.
            Use this if you have problems with upload.
        """
        if rbf is None:
            raise RemoteFileNotFound(
                '''Specified "rbf" is None. Probably the File you're trying '''
                '''to update was removed from the Remote, but still present '''
                '''in your Local Box. Try to Sync them firstly.'''
            )
        return await self._push_file(pf,
            message_to_edit=rbf._message,
            progress_callback=progress_callback,
            use_slow_upload=use_slow_upload)

    async def delete_files(
            self,

            *rbf: Union[
                'EncryptedRemoteBoxFile',
                'DecryptedRemoteBoxFile'
            ],
            rbf_ids: Optional[list] = None,

            lb: Optional[
                Union[
                    'tgbox.api.local.EncryptedLocalBox',
                    'tgbox.api.local.DecryptedLocalBox'
                ]
            ] = None) -> None:
        """
        A function to remove a bunch of remote files
        at once. You need to have some admin rights.

        Arguments:
            rbf (``EncryptedRemoteBoxFile``, ``DecryptedRemoteBoxFile``, asterisk):
                ``(Encrypted|Decrypted)RemoteBoxFile(s)`` to remove.

            rbf_ids (``list``, optional):
                You can specify ids instead of RemoteBox file
                objects. However, ``rbf`` is preferred here.

            lb (``EncryptedLocalBox``, ``DecryptedLocalBox``, optional):
                You can specify a *LocalBox* associated
                with current *RemoteBox* to also remove
                all specified files in *LocalBox* too.

        .. note::
            If you want to delete files only from
            your LocalBox then you can use the
            same method on your LocalBoxFile.
        """
        rbf_ids = rbf_ids if rbf_ids else []
        rbf_ids.extend(rbf_.id for rbf_ in rbf)

        logger.info(f'Removing {len(rbf_ids)} remote files...')

        rm_result = await self._tc.delete_messages(
            entity = self._box_channel,
            message_ids = rbf_ids
        )
        if not rm_result[0].pts_count:
            raise NotEnoughRights(
                '''You don\'t have enough rights to delete '''
                '''files from this RemoteBox.'''
            )
        if lb:
            await lb.delete_files(lbf_ids=rbf_ids)

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
        return make_requestkey(basekey, box_salt)

    async def left(self) -> None:
        """
        With calling this method you will left
        *RemoteBox* ``Channel``.
        """
        await self._tc.delete_dialog(self._box_channel)

    async def delete(self) -> None:
        """
        This method **WILL DELETE** *RemoteBox*!

        Use ``left()`` if you **only want to left**
        your *Box* ``Channel``, not delete it.

        You need to have admin rights for this.
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
        from tgbox.api import get_localbox, get_remotebox
        from tgbox.keys import make_basekey, Phrase

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await dlb.get_localbox(basekey)
            drb = await get_remotebox(dlb)

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
        self._is_encrypted = False

        self._erb = erb
        self._tc = erb._tc

        self._box_channel = erb._box_channel
        self._box_channel_id = erb._box_channel_id

        self._box_salt = erb._box_salt
        self._description = erb._description
        self._box_name = erb._box_name

        self._dlb = dlb

        if self._dlb:
            logger.debug('DecryptedRemoteBox is decrypted with the DLB')
            self._mainkey = self._dlb._mainkey
            self._defaults = self._dlb._defaults
        else:
            if not key:
                raise ValueError('Must be specified at least key or dlb')

            if isinstance(key, (MainKey, ImportKey)):
                logger.debug('DecryptedRemoteBox is decrypted with the MainKey')
                self._mainkey = MainKey(key.key)
            elif isinstance(key, BaseKey):
                logger.debug('DecryptedRemoteBox is decrypted with the BaseKey->MainKey')
                self._mainkey = make_mainkey(key, self._box_salt)
            else:
                raise IncorrectKey('key is not Union[MainKey, ImportKey, BaseKey]')

            self._defaults = erb._defaults

    @property
    def mainkey(self) -> MainKey:
        """Will return ``MainKey`` of this *Box*"""
        return self._mainkey

    @staticmethod
    async def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedRemoteBox`` """
            """and cannot be used on ``DecryptedRemoteBox``."""
        )
    async def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this Box.
        You should use this method if you want
        to share your ``RemoteBox`` with other people.

        Arguments:
            reqkey (``RequestKey``, optional):
                Requester's ``RequestKey``. If isn't specified
                returns ``ShareKey`` of this box without
                encryption, so anyone with this key can
                decrypt **ALL** files in your ``RemoteBox``.
        """
        box_salt = await self.get_box_salt()

        if reqkey:
            return make_sharekey(self._mainkey, box_salt, reqkey)

        return make_sharekey(self._mainkey)

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
        from tgbox.api import get_remotebox, get_localbox

        async def main():
            dlb = await get_localbox(basekey)
            drb = await get_remotebox(dlb)

            erbf = await drb.get_file(
                id = await dlb.get_last_file_id(),
                decrypt = False
            )
            print(erbf.file_salt.hex())
            print(erbf.box_salt.hex())

        asyncio_run(main())
    """
    def __init__(
            self, id: int, erb: EncryptedRemoteBox,
            message_document: Optional[Message] = None,
            cache_preview: bool=True,
            defaults: Optional[Union[DefaultsTableWrapper,
                RemoteBoxDefaults]] = None):
        """
        Arguments:
            id (``int``):
                File ID. You can also specify a
                ``message_document`` if you already
                have ``Message`` object.

            erb (``EncryptedRemoteBox``):
                Encrypted RemoteBox.

            message_document (``Message``, optional):
                A ``Telethon``'s message object. This
                message should contain ``File``. If
                specified, the ``id`` argument will
                be ignored.

            cache_preview (``bool``, optional):
                Cache preview in class or not.

            defaults (``DefaultsTableWrapper``, ``RemoteBoxDefaults``):
                Class with a default values/constants we will use.
        """
        self._initialized = False
        self._is_encrypted = True
        self._cache_preview = cache_preview

        self._rb = erb

        if message_document:
            self._message = message_document
            self._id = self._message.id
        else:
            self._message = None
            self._id = id

        self._file = None
        self._sender = None

        self._upload_time = None
        self._updated_at_time = None
        self._box_channel = None
        self._box_channel_id = None
        self._file_size = None
        self._file_file_name = None

        self._metadata = None
        self._file_iv = None

        self._file_salt = None
        self._box_salt = None
        self._version_byte = None
        self._prefix = None
        self._fingerprint = None
        self._secret_metadata = None
        self._efile_path = None
        self._minor_version = None

        self._file_pos = None
        self._imported = None

        if defaults is None:
            logger.debug('ERBF: Custom defaults is not present')

            self._defaults = RemoteBoxDefaults(
                METADATA_MAX = Limits.METADATA_MAX,
                FILE_PATH_MAX = Limits.FILE_PATH_MAX,
                DEF_UNK_FOLDER = DEF_UNK_FOLDER,
                DEF_NO_FOLDER = DEF_NO_FOLDER,
                DOWNLOAD_PATH = DOWNLOAD_PATH)
        else:
            logger.debug('ERBF: Found custom defaults, will try to use it')
            self._defaults = defaults

    def __repr__(self) -> str:
        return (
            f'''{self.__class__.__name__}({self._id}, {repr(self._rb)}, '''
            f'''{self._message}, {self._cache_preview}, {repr(self._defaults)})'''
        )
    def __str__(self) -> str:
        file_salt = None if not self._initialized else urlsafe_b64encode(self._file_salt.salt).decode()
        return (
            f'''{self.__class__.__name__}({self._id}, {repr(self._rb)}, '''
            f'''{self._message}, {self._cache_preview}, {repr(self._defaults)}) # '''
            f'''{self._initialized=}, {file_salt=}, {self._sender=}, {self._imported=}'''
        )
    def __hash__(self) -> int:
        if not self.initialized:
            raise NotInitializedError(
                'Must be initialized before hashing'
            )
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
    def is_encrypted(self) -> bool:
        """
        Will return ``True`` if this is an *Encrypted*
        class, ``False`` if *Decrypted*
        """
        return self._is_encrypted

    @property
    def rb(self) -> Union[EncryptedRemoteBox, DecryptedRemoteBox]:
        """
        Returns ``EncryptedRemoteBox`` from ``EncryptedRemoteBoxFile``
        and ``DecryptedRemoteBox`` from ``DecryptedRemoteBoxFile``
        """
        return self._rb

    @property
    def defaults(self) -> Union[DefaultsTableWrapper, RemoteBoxDefaults]:
        """
        Will return ``DefaultsTableWrapper`` or
        ``RemoteBoxDefaults``.
        """
        return self._defaults

    @property
    def sender(self) -> Union[str, None]:
        """
        Returns post author if sign
        messages is enabled in
        ``Channel``, ``None`` otherwise
        """
        return self._sender

    @property
    def imported(self) -> bool:
        """
        Returns ``True`` if file was imported
        from other RemoteBox. ``False`` otherwise.
        """
        return self._imported

    @property
    def version_byte(self) -> Union[bytes, None]:
        """Returns Verbyte or ``None`` if not initialized"""
        return self._version_byte

    @property
    def minor_version(self) -> Union[int, None]:
        """Returns Minor Version of this file or
        ``None`` if class wasn't initialized. If
        it's a -1, then file was uploaded before
        the version 1.3.0 and minor is unknown.
        """
        return self._minor_version

    @property
    def box_salt(self) -> Union[BoxSalt, None]:
        """Returns ``BoxSalt`` or ``None`` if not initialized"""
        return self._box_salt

    @property
    def fingerprint(self) -> Union[bytes, None]:
        """
        Returns file fingerprint (hash of
        file path plus mainkey) or ``None``
        """
        return self._fingerprint

    @property
    def upload_time(self) -> Union[int, None]:
        """Returns upload time or ``None`` if not initialized"""
        return self._upload_time

    @property
    def updated_at_time(self) -> Union[int, None]:
        """Returns time when file was updated or ``None`` if not initialized"""
        return self._updated_at_time

    @property
    def file_salt(self) -> Union[FileSalt, None]:
        """Returns ``FileSalt`` or ``None`` if not initialized"""
        return self._file_salt

    @property
    def file_iv(self) -> Union[IV, None]:
        """Returns ``IV`` or ``None`` if not initialized"""
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
    def message(self) -> Message:
        """Returns Telethon's ``Message`` object."""
        return self._message

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
        """Returns ID of the RemoteBox ``Channel``."""
        return self._box_channel_id

    @property
    def box_channel(self) -> Channel:
        """Returns RemoteBox ``Channel`` object."""
        return self._box_channel

    @property
    def prefix(self) -> Union[bytes, None]:
        """Returns file prefix or ``None`` if not initialized"""
        return self._prefix

    def __raise_initialized(self) -> NoReturn:
        if not self.initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

    async def init(self, verify_prefix: bool=True) -> 'EncryptedRemoteBoxFile':
        """
        This method will download and set raw
        RemoteBoxFile metadata. If metadata length
        is bigger than ``self.defaults.METADATA_MAX``
        then ``errors.LimitExceeded`` will be raised.

        Arguments:
            verify_prefix (``bool``, optional):
                If ``True``, will check that file has a
                ``defaults.PREFIX`` in metadata, and if
                not, will raise a ``NotATgboxFile`` exception.
        """
        logger.info(f'Initializing EncryptedRemoteBoxFile (ID{self._id})...')

        if isinstance(self._defaults, DefaultsTableWrapper):
            if not self._defaults.initialized:
                await self._defaults.init()

        # ======================================================= #

        if not self._message:
            self._message = await self._rb._tc.get_messages(
                self._rb.box_channel, ids=self._id)

        self._file = self._message.file
        self._file_file_name = self._file.name

        if not self._file:
            raise NotATgboxFile('Specified message doesn\'t have a document')

        self._file_size = self._file.size

        self._sender = self._message.post_author
        self._upload_time = int(self._message.date.timestamp())

        if self._message.edit_date:
            self._updated_at_time = int(self._message.edit_date.timestamp())
        else:
            self._updated_at_time = self._upload_time

        self._box_channel = self._message.chat
        self._box_channel_id = self._message.peer_id.channel_id

        if self._message.fwd_from:
            self._imported = True
        else:
            self._imported = False

        # ======================================================= #

        # 3 is amount of bytes to which we pack metadata length
        request_amount = len(PREFIX) + len(VERBYTE) + 3

        logger.debug(f'base_data request_amount is {request_amount} bytes')

        async for base_data in self._rb._tc.iter_download(
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
                if metadata_size > self._defaults.METADATA_MAX:
                    raise LimitExceeded(f'{self._defaults.METADATA_MAX=}, {metadata_size=}.')

                # We will also download IV. It's not included
                # in the total metadata bytesize.
                metadata_size += 16
                break

        if metadata_size > self._defaults.METADATA_MAX:
            raise LimitExceeded(f'{metadata_size=} > {self._defaults.METADATA_MAX=}')

        logger.debug(f'metadata_size is {metadata_size} bytes')

        if metadata_size <= 1048576:
            metadata_size_padded = pad_request_size(metadata_size)
        else:
            metadata_size_padded = metadata_size

        logger.debug(f'metadata_size_padded is {metadata_size_padded} bytes')

        iter_down = self._rb._tc.iter_download(
            file = self._message.document,
            offset = request_amount,
            request_size = metadata_size_padded
        )
        async for metadata in iter_down:
            m = self._prefix + self._version_byte
            m += int_to_bytes(metadata_size,3)
            self._metadata = m + bytes(metadata[:metadata_size])
            self._file_pos = len(self._metadata)
            logger.debug(f'Actual encrypted filedata position: {self._file_pos}')
            break

        parsedm = PackedAttributes.unpack(self._metadata[len(m):-16])

        self._file_iv = IV(self._metadata[-16:])

        self._file_salt = FileSalt(parsedm['file_salt'])
        self._box_salt = BoxSalt(parsedm['box_salt'])
        self._secret_metadata = parsedm['secret_metadata']
        # Fingerprint was added in the v1.1. It's a SHA256 over
        # absolute Box file_path and MainKey. If it's not
        # presented in the Metadata, then it's a file of v1.0
        self._fingerprint = parsedm.get('file_fingerprint', b'')

        # Metadata include the minor_version field started from
        # the version 1.3. We use it to enable a more
        # straightforward backward compatibility
        self._minor_version = parsedm.get('minor_version', -1)
        if isinstance(self._minor_version, bytes):
            self._minor_version = bytes_to_int(self._minor_version)

        if self._minor_version >= 3:
            # efile_path is encrypted File's path. Previously
            # it was in the Secret Metadata. Now it's a part
            # public Metadata and we will decrypt it and use
            # to make a DirectoryKey and then a FileKey
            self._efile_path = parsedm['efile_path']
        else:
            self._efile_path = None

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
        logger.debug(f'Removing file ID{self._id} from ID{self._box_channel_id}')

        rm_result = await self._rb._tc.delete_messages(
            self._box_channel, [self._id]
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
        return make_requestkey(mainkey, self._file_salt)

    async def decrypt(
            self, key: Optional[Union[MainKey, FileKey, ImportKey]] = None,
            drb: Optional[DecryptedRemoteBox] = None,
            erase_encrypted_metadata: bool=True
            ) -> 'DecryptedRemoteBoxFile':
        """
        Returns ``DecryptedRemoteBoxFile``.

        Arguments:
            key (``FileKey``, ``MainKey``, ``ImportKey``):
                Decryption key. Must be specified if
                ``drb`` argument is ``None``.

            drb (``DecryptedRemoteBox``, optional):
                Decrypted RemoteBox. Must be specified
                if ``key`` argument is ``None``.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedRemoteBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        if not self.initialized:
            await self.init()

        return DecryptedRemoteBoxFile(self, key=key, drb=drb,
            erase_encrypted_metadata=erase_encrypted_metadata)

class DecryptedRemoteBoxFile(EncryptedRemoteBoxFile):
    """
    This class represents decrypted remote file.
    You can retrieve all metadata info from properties.

    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_localbox, get_remotebox
        from tgbox.keys import Phrase, make_basekey

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_localbox(basekey)
            drb = await get_remotebox(dlb)

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
            key: Optional[Union[FileKey, ImportKey, MainKey]] = None,
            drb: Optional[DecryptedRemoteBox] = None,
            cache_preview: Optional[bool] = None,
            erase_encrypted_metadata: bool=True):
        """
        Arguments:
            erbf (``EncryptedRemoteBoxFile``):
                Instance of ``EncryptedRemoteBoxFile`` to decrypt.

            key (``FileKey``, ``ImportKey``, ``MainKey``, optional):
                Decryption key. Must be specified
                if ``drb`` argument is ``None``.

            drb (``DecryptedRemoteBox``, optional):
                Decrypted RemoteBox associated with the
                EncryptedRemoteBoxFile you want to decrypt.
                Must be specified if ``key` is ``None``.

            cache_preview (``bool``, optional):
                Cache preview in class or not. If it's
                ``None`` (by default) will be inherited
                the same ``cache_preview`` from parent.

            erase_encrypted_metadata (``bool``, optional):
                If ``True`` (by default) will remove the
                encrypted ``secret_metadata`` Metadata
                value from the parent class.
        """
        if not any((key, drb)):
            raise ValueError('At least key or drb must be specified')

        if not erbf.initialized:
            raise NotInitializedError('EncryptedRemoteBoxFile must be initialized.')

        self._key = key
        self._erbf = erbf

        if drb:
            self._rb = drb
        else:
            self._rb = erbf._rb

        self._initialized = False
        self._is_encrypted = False

        self.__required_metadata = [
            'duration', 'file_size', 'file_name',
            'cattrs', 'mime', 'preview'
        ]
        self._message = erbf._message
        self._id = erbf._id
        self._file = erbf._file
        self._sender = erbf._sender

        self._defaults = erbf._defaults

        if cache_preview is None:
            self._cache_preview = erbf._cache_preview
        else:
            self._cache_preview = cache_preview

        self._erase_encrypted_metadata = erase_encrypted_metadata

        self._box_channel = erbf._box_channel
        self._box_channel_id = erbf._box_channel_id

        self._box_salt = erbf._box_salt
        self._file_size = erbf._file_size

        self._fingerprint = erbf._fingerprint
        self._minor_version = erbf._minor_version

        self._upload_time, self._size = erbf._upload_time, None
        self._file_iv, self._file_salt = erbf._file_iv, erbf._file_salt
        self._cattrs, self._file_path = None, None
        self._duration, self._version_byte = None, erbf._version_byte
        self._updated_at_time = erbf._updated_at_time

        self._preview, self._imported = None, erbf._imported
        self._prefix, self._file_pos = erbf._prefix, erbf._file_pos

        self._file_file_name = erbf._file_file_name
        self._mime, self._file_name = None, None
        self._residual_metadata = None


        if isinstance(key, MainKey):
            logger.debug('key is MainKey, self._mainkey is present')
            self._mainkey = key

        elif isinstance(self._rb, DecryptedRemoteBox):
            logger.debug('We will take MainKey from DecryptedRemoteBox')
            self._mainkey = self._rb._mainkey
        else:
            self._mainkey = None


        # Prior to v1.3, the EFILE_PATH was a part of the Secret Metadata,
        # thus, was *always* None before decryption. Started from the v1.3,
        # the EFILE_PATH is now in a Public Metadata, so we can easily
        # decrypt it with MainKey, then make a DirectoryKey, and then
        # make a FileKey, which will decrypt File and Secret Metadata.
        # This "If Statement" will be True only if File is version 1.3+
        if self._mainkey and erbf._efile_path is not None and not self._imported:
            try:
                self._file_path = AES(self._mainkey).decrypt(erbf._efile_path)
            except ValueError: # ValueError: invalid padding byte
                logger.info(
                   f'''We can\'t decrypt real file path of ID{self._id} because '''
                    '''MainKey is not presented. Try to decrypt EncryptedRemoteBoxFile '''
                    '''with MainKey to fix this. Setting to DEF_NO_FOLDER...'''
                )
                self._file_path = self._defaults.DEF_NO_FOLDER
                self._dirkey = None
            else:
                self._file_path = make_general_path(self._file_path.decode())

                for path_part in ppart_id_generator(self._file_path, self._mainkey):
                    ppath_head = path_part[2]

                self._dirkey = make_dirkey(self._mainkey, ppath_head)
        else:
            if erbf._efile_path: # v1.3+ but no MainKey
                logger.info(
                   f'''We can\'t decrypt real file path of ID{self._id} because '''
                    '''MainKey is not presented. Try to decrypt EncryptedRemoteBoxFile '''
                    '''with MainKey to fix this. Setting to DEF_NO_FOLDER...'''
                )
                self._file_path = self._defaults.DEF_NO_FOLDER

            self._dirkey = None

        secret_metadata = None

        if isinstance(key, FileKey):
            logger.debug('Treating key as FileKey')
            self._filekey = FileKey(key.key)

        elif isinstance(key, ImportKey):
            try:
                logger.debug('Trying to treat key as DirectoryKey...')

                filekey = make_filekey(key, self._file_salt)

                secret_metadata = AES(filekey).decrypt(
                    self._erbf._secret_metadata
                )
                secret_metadata = PackedAttributes.unpack(secret_metadata)
                assert secret_metadata # Shouldn't be empty dict.
                # ^ ImportKey can be DirectoryKey, so here we're try
                #   to treat it as dirkey and make FileKey from it,
                #   then, we try to decrypt secret Metadata field to
                #   check if decryption will fail or not. If not, --
                #   it's definitely a DirectoryKey.
                #
                # | Decryption can fail with ValueError (invalid
                #   padding bytes OR by `assert` statement.
                self._filekey = filekey
                self._dirkey = DirectoryKey(key)
            except (ValueError, AssertionError):
                logger.debug('ImportKey is not DirectoryKey, so treating as FileKey')
                self._filekey = FileKey(key.key)

        elif self._mainkey:
            if self._dirkey:
                logger.debug('Making FileKey from the DirectoryKey and FileSalt (>= v1.3)')
                self._filekey = make_filekey(self._dirkey, self._file_salt)
            else:
                logger.debug('Making FileKey from the MainKey and FileSalt (< v1.3)')
                self._filekey = make_filekey(self._mainkey, self._file_salt)

        else:
            raise ValueError('You need to specify FileKey | MainKey | DecryptedLocalBox')

        logger.debug('Decrypting & Unpacking secret_metadata of ERBF metadata...')

        if not secret_metadata:
            try:
                secret_metadata = AES(self._filekey).decrypt(
                    self._erbf._secret_metadata
                )
            except ValueError:
                raise AESError('Metadata wasn\'t decrypted correctly. Incorrect key?')

            secret_metadata = PackedAttributes.unpack(secret_metadata)

        if not secret_metadata: # secret_metadata can't be empty dict
            raise AESError('Metadata wasn\'t decrypted correctly. Incorrect key?')

        if self._cache_preview:
            logger.debug('cache_preview is True, DRBF preview will be saved.')
            self._preview = secret_metadata['preview']
        else:
            logger.debug('cache_preview is False, DRBF preview won\'t be saved.')
            self._preview = b''

        self._duration = bytes_to_int(secret_metadata['duration'])
        self._size = bytes_to_int(secret_metadata['file_size'])
        self._file_name = secret_metadata['file_name'].decode()
        self._cattrs = PackedAttributes.unpack(secret_metadata['cattrs'])
        self._mime = secret_metadata['mime'].decode()

        if self._file_path is None:
            # File was uploaded from Version < 1.3
            if self._mainkey and not self._imported:
                logger.debug('Decrypting efile_path with the MainKey')
                self._file_path = AES(self._mainkey).decrypt(
                    secret_metadata['efile_path']
                )
                self._file_path = Path(self._file_path.decode())
            else:
                logger.info(
                   f'''We can\'t decrypt real file path of ID{self._id} because '''
                    '''MainKey is not presented. Try to decrypt EncryptedRemoteBoxFile '''
                    '''with MainKey to fix this. Setting to DEF_NO_FOLDER...'''
                )
                self._file_path = self._defaults.DEF_NO_FOLDER

            # Started from the v1.3, the EFILE_PATH is not a
            # part of the Required Metadata fields.
            secret_metadata.pop('efile_path')

        # Started from the v1.5, Secret Metadata contains a 'has_hmac_sha256'
        # key. If it's presented, then we should check file HMAC on download
        self._has_hmac_sha256 = bool(secret_metadata.pop('has_hmac_sha256', None))

        if self._has_hmac_sha256:
            # _BFP is Pseudo-random bytes that protect first block
            # of AES CBC against the Bit-flipping attack on IV.
            secret_metadata.pop('_BFP') # version 1.5+ (if has_hmac_sha256)
            self._hmackey = make_hmackey(self._filekey, self._file_salt)
        else:
            if self._minor_version >= 5:
                raise InvalidFile(
                   f'Your Local File ID{self._id} does NOT have "has_hmac_sha256" '
                    'key, however, it is REQUIRED from version v1.5. Either your '
                    'Secret Metadata was changed by a stupid attacker or there is '
                    'another problem with Metadata. Consider to review peoples '
                    'that have access (editing/posing) to your RemoteBox Channel '
                    'and then re-upload this file. DO NOT TRUST IT!!!'
                )
            self._hmackey = None # File was uploaded from version < 1.5

        for attr in self.__required_metadata:
            secret_metadata.pop(attr)

        self._residual_metadata = secret_metadata

        # Here, "self._message.message.startswith('<')" check is for
        # temporary '<This caption must be removed>' caption on
        # 'push_file()'. Base64 doesn't have '<' character, so
        # it's either this message or User specified thing.
        if self._message.message and not self._message.message.startswith('<'):
            try:
                edited_metadata = AES(self._filekey).decrypt(
                    urlsafe_b64decode(self._message.message)
                )
                edited_metadata = PackedAttributes.unpack(edited_metadata)
                logger.debug(f'Updates to metadata for ID{self._id} found. Applying...')

                for k,v in tuple(edited_metadata.items()):
                    if k in (*self.__required_metadata, 'efile_path'):
                        if k == 'cattrs':
                            self._cattrs.update(PackedAttributes.unpack(v))

                        elif k == 'duration':
                            setattr(self, f'_{k}', bytes_to_int(v))

                        elif k == 'efile_path':
                            if self._mainkey:
                                file_path = AES(self._mainkey).decrypt(v)
                                self._file_path = Path(file_path.decode())
                            else:
                                logger.debug(
                                    '''Updated metadata contains efile_path, but '''
                                    '''this DecryptedRemoteBoxFile wasn\'t '''
                                    '''decrypted with MainKey, so we will ignore it'''
                                )
                        else:
                            # str attributes
                            if k in ('mime', 'file_name'):
                                setattr(self, f'_{k}', v.decode())
                            else:
                                setattr(self, f'_{k}', v)
                    else:
                        self._residual_metadata[k] = v

                    del edited_metadata[k]

            except Exception:
                logger.info(
                    f'''Updates to metadata for ID{self._id} failed. '''
                    f'''Traceback:\n{format_exc()}'''
                )
        self._initialized = True

        if self._erase_encrypted_metadata:
            self._erbf._initialized = False
            self._erbf._secret_metadata = None
            self._erbf._metadata = None

    @property
    def has_hmac_sha256(self) -> bool:
        """Will return ``True`` if file has HMAC (v1.5+)"""
        return self._has_hmac_sha256

    @property
    def hmackey(self) -> Union[HMACKey, None]:
        """Returns ``HMACKey`` of this file if present."""
        return self._hmackey

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
        """Returns preview bytes or ``b''`` if not initialized."""
        return self._preview

    @property
    def file_iv(self) -> Union[IV, None]:
        """Returns ``IV`` or ``None`` if not initialized."""
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
        """
        Will change self._file_path to file_path.
        In most cases you don't need to use this
        """
        self._file_path = file_path

    @property
    def file_name(self) -> Union[str, None]:
        """Returns file name or ``None`` if not initialized."""
        return self._file_name

    @property
    def file_salt(self) -> Union[FileSalt, None]:
        """Returns ``FileSalt`` or ``None`` if not initialized."""
        return self._file_salt

    @property
    def filekey(self) -> FileKey:
        """Returns ``FileKey`` of this file."""
        return self._filekey

    @property
    def dirkey(self) -> Union[DirectoryKey, None]:
        """Returns ``DirectoryKey`` of this file if present."""
        return self._dirkey

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

    @staticmethod
    async def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedRemoteBoxFile`` """
            """and cannot be used on ``DecryptedRemoteBoxFile``."""
        )
    @staticmethod
    async def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedRemoteBoxFile`` """
            """and cannot be used on ``DecryptedRemoteBoxFile``."""
        )
    async def download(
            self, *, outfile: Optional[Union[str, BinaryIO, Path]] = None,
            hide_folder: bool=False, hide_name: bool=False,
            decrypt: bool=True, request_size: int=524288,
            offset: Optional[int] = None,
            progress_callback: Optional[Callable[[int, int], None]] = None,
            use_slow_download: Optional[bool] = False,
            hmac_state: Optional[HMAC] = None,
            omit_hmac_check: Optional[bool] = False) -> BinaryIO:
        """
        Downloads and saves remote box file to the ``outfile``.

        Arguments:
            oufile (``str``, ``BinaryIO``, ``PathLike``, optional):
                Path-like or File-like object to which file
                will be downloaded. ``self.defaults.DOWNLOAD_PATH`` by default.

                If ``outfile`` has ``.write()`` method then we will use it.

                If ``outfile`` is ``str`` or ``Path`` and ``offset``, --
                we will open in ``ab+`` mode, ``wb`` otherwise.

                If ``outfile`` is your custom object, then you need to
                implement a ``.write()`` at minumum. If you download
                from ``offset`` then also ``.read()`` and ``.seek()``
                or pass ``hmac_state`` as keyword argument instead.

            hide_folder (``bool``, optional):
                Saves to folder which this file belongs to if False,
                (default) otherwise to ``outfile/{self.defaults.DEF_UNK_FOLDER}``.

                * Doesn't create any folders if ``isinstance(outfile, BinaryIO)``.

            hide_name (``bool``, optional):
                Saves file with random name if ``True``, with
                original if ``False`` (default).

                * File extension (e.g ``.png``) included in both cases.
                * Doesn't create any folders if ``isinstance(outfile, BinaryIO)``.

            decrypt (``bool``, optional):
                Decrypts file if True (default).

            offset (``int``, optional):
                Offset to **decrypted** file. Use this if your download
                process was stopped for some reason. Specify here how
                much of bytes you already downloaded and we will fetch rest.

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

            use_slow_download (``bool``, optional):
                Will use default download function from the Telethon
                library instead of function from `fastelethon.py`.
                Use this if you have problems with download.

            hmac_state (``hmac.HMAC``, optional):
                If you download file from some ``offset`` and your
                ``outfile`` is NOT readable, then we can't compute
                and verify the HMAC checksum. In this case, you
                will need to provide a ``hmac.HMAC`` state with
                bytes updated up to the ``offset``. For example:

                .. code-block:: python

                    ... # Most code was omited

                    from hmac import HMAC

                    # Let's assume that our download process was
                    # disrupted by some event. We already fetched
                    # big part of file, so we don't want to make a
                    # full re-download. Also, we assume that we
                    # download to custom 'outfile' which is NOT
                    # readable (for example, here we will open it
                    # in 'ab' mode, however, 'ab+' would be readable)

                    outfile = open('video.mp4','ab') # NOT readable!

                    # This is corresponding file that we want to download
                    drbf = await drb.get_file(dlb.get_last_file_id())

                    # Create 'hmac_state' and init with DRBF 'HMACKey'
                    hmac_state = HMAC(drbf.hmackey.key, digestmod='sha256')

                    # Now we need to update a 'hmac_state' with bytes
                    # that we already downloaded. AGAIN, this is a
                    # STUPID example. If you can make the 'outfile'
                    # readable (i.e 'ab+'), then just pass it to
                    # 'download()' method as is! OTHERWISE:

                    with open(outfile.name,'rb') as f:
                        hmac_state.update(f.read()) # Update hmac_state
                        offset = f.tell() # Easily retrieve offset

                    await drbf.download(
                        outfile=outfile,
                        offset=offset,
                        hmac_state=hmac_state
                    )
                    # This is just example with 'open()'. If you
                    # have custom object as 'outfile' then you need
                    # to made it in different way suitable for you

            omit_hmac_check (``bool``, optional):
                Will omit HMAC check on download if ``True``. As
                we make HMAC of plaintext on upload, HMAC check
                be always skipped if ``decrypt`` is ``False``.
        """
        self.__raise_initialized()

        logger.info(f'Downloading DRBF (ID{self._id})...')

        if not decrypt:
            # We can't calculate HMAC without plaintext
            omit_hmac_check = True

        if outfile is None:
            outfile = self._defaults.DOWNLOAD_PATH

        if isinstance(outfile, (str, PathLike)):
            outfile = Path(outfile)
            outfile.mkdir(exist_ok=True, parents=True)

            path = self._defaults.DEF_UNK_FOLDER if hide_folder else self._file_path
            # The first '/' symbol in '/home/non/' is also path part,
            # so we need to create a folders like / -> home -> non,
            # however, Linux (and i believe all UNIX) OS doesn't allow
            # to use a '/' symbol in filename, so instead of / we use
            # a '@' while creating path. You can refer to it as root.
            #
            # In Windows paths [i.e C:\Users\user] the first path
            # part (anchor) is 'C:\\'. We will remove all but
            # letter to prevent strange behaviour on Windows
            #
            # The make_safe_file_path() func do this for us
            path = make_safe_file_path(path)

            if hide_name:
                name = prbg(16).hex() + Path(self._file_name).suffix
            else:
                name = self._file_name

            outfile = Path(outfile, path, name.lstrip('/'))
            outfile.parent.mkdir(exist_ok=True, parents=True)

            if offset:
                if hmac_state or omit_hmac_check:
                    # We don't need to read outfile
                    outfile = open(outfile,'ab')
                else:
                    outfile = open(outfile,'ab+')
            else:
                outfile = open(outfile,'wb')

        elif isinstance(outfile, BinaryIO) or hasattr(outfile, 'write'):
            pass # We already can write
        else:
            raise TypeError('outfile not Union[BinaryIO, str, PathLike].')

        logger.debug(f'outfile is {outfile}')

        # '0' is the fast download from the fastelethon.py, and '1'
        # is the default download from Telethon library.
        download_error_switch = 1 if use_slow_download else 0

        stream_iv = self._file_iv if not offset else b'' # We know IV if (not offset)
        aws = None # Placeholder for AESwState class, we will set it later
        offset = 0 if not offset else offset

        download_offset = self._file_pos + offset
        if offset:
            download_offset -= 16 # Currently i don't know why but without this
                # first block decryption works incorrectly if offset specified.

        # Download offset must be divisible by 4096 & 524288
        download_offset_prepared = int((download_offset // 4096) * 4096)
        download_offset_prepared = int((download_offset_prepared // 524288) * 524288)

        while True:
            # We need previous AES CBC block to obtain IV for the next one,
            # but Telegram give only 512KiB blocks, so we need to download it
            if not stream_iv and decrypt:
                if offset:
                    assert not offset % 524288, 'offset must be divisible by 524288'
                    iv_offset = self._file_pos + (offset - 524288)
                else:
                    iv_offset = self._file_pos - 524288
                    iv_offset -= (iv_offset % 524288)
                    iv_offset = 0 if iv_offset < 0 else iv_offset

                iter_down_iv = self._rb._tc.iter_download(
                    self._message.document,
                    offset=iv_offset
                )
                for _ in range(2):
                    stream_iv += bytes(await anext(iter_down_iv, b''))

                stream_iv_pos = self._file_pos + offset - 16
                stream_iv = stream_iv[stream_iv_pos:stream_iv_pos+16]

            if decrypt:
                aws = AES(self._filekey, stream_iv)

            if not omit_hmac_check and self._has_hmac_sha256:
                if not hmac_state:
                    hmac_state = HMAC(self.hmackey.key, digestmod='sha256')

                    if offset:
                        if not outfile.readable():
                            raise ValueError(
                                'outfile is not readable, can not check HMAC. '
                                'Either make outfile readable [Good] or use '
                                'omit_hmac_check [Bad]'
                            )
                        outfile.seek(0,0) # Seek to start of file

                        try:
                            # Update 'hmac_state' with 128MB chunks
                            while (read_ := outfile.read(128000000)):
                                hmac_state.update(read_)
                        except Exception as e:
                            raise ValueError('Can not read outfile to make HMAC') from e
            else:
                logger.info('"omit_hmac_check" is True, so HMAC check was disabled')
            try:
                # By default we will try to download file via the
                # fast "download_file" coroutine from fastelethon
                # module. If it fails, the "download_error_switch"
                # will be incremented and this code will be switched
                # to the default "iter_download" from TelegramClient;
                # If it will fail too, -- we will raise an error.
                if download_error_switch == 0:
                    iter_down = download_file(
                        client = self._rb._tc,
                        location = self._message.document,
                        request_size = request_size,
                        offset = download_offset_prepared)
                else:
                    # Switch to the default slow method
                    iter_down = self._rb._tc.iter_download(
                        self._message.document,
                        request_size = request_size,
                        offset = download_offset_prepared
                    )

                buffered, total = b'', offset
                async for chunk in iter_down:
                    if buffered:
                        buffered += chunk
                        chunk = buffered[:request_size]
                        buffered = buffered[request_size:]
                    else:
                        slice_ = download_offset - download_offset_prepared
                        buffered += chunk[slice_:]
                        continue

                    total += len(chunk)

                    if total > self._size:
                        total = self._size

                    logger.debug(
                        f'''ID{self._id}: Downloading... {total=} '''
                        f'''from the {self._size=} bytes; {len(buffered)=}'''
                    )
                    if total == self._size and not buffered:
                        if self._has_hmac_sha256:
                            file_hmac = chunk[-32:]
                            chunk = chunk[:-32]

                        logger.debug(f'ID{self._id}: Writing last bytes (Unpad)...')
                        chunk = aws.decrypt(chunk, unpad=True) if decrypt else chunk
                    else:
                        chunk = aws.decrypt(chunk, unpad=False) if decrypt else chunk

                    outfile.write(chunk)

                    if not omit_hmac_check and self._has_hmac_sha256:
                        hmac_state.update(chunk)

                    if progress_callback:
                        if iscoroutinefunction(progress_callback):
                            await progress_callback(total, self._size)
                        else:
                            progress_callback(total, self._size)

                if buffered:
                    logger.debug(
                        f'ID{self._id}: Writing last buffered bytes (Unpad)...'
                    )
                    if self._has_hmac_sha256:
                        file_hmac = buffered[-32:]
                        buffered = buffered[:-32]

                    chunk = aws.decrypt(buffered, unpad=True) if decrypt else chunk
                    outfile.write(chunk)

                    if not omit_hmac_check and self._has_hmac_sha256:
                        hmac_state.update(chunk)

                    if progress_callback:
                        if iscoroutinefunction(progress_callback):
                            await progress_callback(self._size, self._size)
                        else:
                            progress_callback(self._size, self._size)

                if not omit_hmac_check and self._has_hmac_sha256:
                    if not hmac_compare_digest(file_hmac, hmac_state.digest()):
                        raise InvalidFile(
                           f'File ID={self._id} was modified!!!! Calculated '
                           f'HMAC is {hmac_state.digest().hex()=}, but HMAC '
                           f'attached to Remote File is {file_hmac.hex()=}. '

                           f'DO NOT TRUST downloaded data of File ID={self._id}! '
                           f'File name: {self._file_name}, Outfile: {outfile} '
                            'Consider to review it & then purge!'
                        )

                break # Download is successfull so we can exit this loop

            except Exception as e:
                if isinstance(e, InvalidFile):
                    raise e from e

                if download_error_switch == 0:
                    download_error_switch = 1
                    logger.warning(
                        '''Fast download FAILED. Trying with SLOW!\n'''
                       f'''{format_exc()}''')
                    continue
                else:
                    logger.error('Both fast and slow download methods failed')
                    raise e from e

        return outfile

    async def update_metadata(
            self, changes: Dict[str, Union[bytes, None]],
            dlb: Optional['DecryptedLocalBox'] = None,
            dlbf: Optional['DecryptedLocalBoxFile'] = None
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

                You can change the next fields: 'duration',
                'file_name', 'cattrs', 'mime', 'preview' &
                'file_path'.

                All values *must* be ``bytes``. Use the
                ``tgbox.tools.int_to_bytes`` function for
                'duration' field.

            dlb (``DecryptedLocalBox``, optional):
                ``DecryptedLocalBox`` associated with
                this ``DecryptedRemoteBox``. Will auto
                refresh your updates. If not specified,
                then you will need to do it by yourself.

                If you have ``DecryptedLocalBoxFile``,
                pass it as ``dlbf`` instead.

            dlbf (``DecryptedLocalBoxFile``, optional):
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

            - Not a *default* metadata (default is file_name, mime, etc)
              will be placed to the ``residual_metadata`` property dict.

            - There is a file caption (and so updated metadata)
              limit: 1KB and 2KB for a Premium Telegram users.

            - You can replace file's path by specifying a ``file_path``
              key with appropriate path (str/bytes). Also, you
              **will need** to specify a ``DecryptedLocalBox``
              as ``dlb`` so we can create a new *LocalBoxDirectory*
              from your path. Without it you will get a ``ValueError``
        """
        if 'efile_path' in changes:
            raise ValueError('The "changes" should not contain efile_path')

        if 'file_path' in changes and not dlb:
            raise ValueError('You can\'t change file_path without specifying dlb!')

        current_changes = changes.copy()

        logger.debug(f'Applying changes {current_changes} to the ID{self._id}...')
        try:
            message_caption = urlsafe_b64decode(self._message.message)
            updates = AES(self._filekey).decrypt(message_caption)
            updates = PackedAttributes.unpack(updates)
        except (ValueError, TypeError):
            updates = {}

        new_file_path = current_changes.pop('file_path', None)
        if isinstance(new_file_path, bytes):
            new_file_path = new_file_path.decode()

        if new_file_path:
            directory = await dlb._make_local_path(Path(new_file_path))

            await dlb._tgbox_db.FILES.execute((
                'UPDATE FILES SET PPATH_HEAD=? WHERE ID=?',
                (directory.part_id, self._id)
            ))
            efile_path = AES(dlb._mainkey).encrypt(new_file_path.encode())
            current_changes['efile_path'] = efile_path

        # If new_file_path is empty string then it's should be
        # a request to remove updated file_path attribute
        # from the RemoteBox file and restore default
        if new_file_path is not None:
            updates.pop('efile_path', None)

        # This will update already existed CAttrs in Updated Metadata
        # with new from the "changes" dict. If any key of CAttrs will
        # be with empty value (i.e x=b"") then it will be removed from
        # the Updated Metadata bytestring.
        if 'cattrs' in current_changes:
            changes_cattrs = PackedAttributes.unpack(current_changes.pop('cattrs'))

            if 'cattrs' in updates:
                updates_cattrs = PackedAttributes.unpack(updates.pop('cattrs'))

                for k,v in tuple(changes_cattrs.items()):
                    if not v.strip():
                        changes_cattrs.pop(k)

                        if k in updates_cattrs:
                            updates_cattrs.pop(k)

                updates_cattrs.update({k:v for k,v in changes_cattrs.items()})

                if updates_cattrs:
                    current_changes['cattrs'] = PackedAttributes.pack(**updates_cattrs)
            else:
                changes_cattrs = {k:v for k,v in changes_cattrs.items() if v.strip()}

                if changes_cattrs:
                    current_changes['cattrs'] = PackedAttributes.pack(**changes_cattrs)

        updates.update(current_changes)

        for k,v in tuple(updates.items()):
            if not v:
                del updates[k]

                if k in self._residual_metadata:
                    del self._residual_metadata[k]

        updates.pop('_BFP', None) # Remove previous _BFP

        if updates:
            # "protection" is a Bit-flipping attack protection
            # for the first AES CBC block. Garbage due to non-IV
            # bit-flipped blocks will invalidate PackedAttributes
            protection = PackedAttributes.pack(_BFP=prbg(5))
            updates_packed = PackedAttributes.pack(**updates)
            updates_packed = protection + updates_packed[1:]

            updates_encrypted = AES(self._filekey).encrypt(updates_packed)
            updates_encoded = urlsafe_b64encode(updates_encrypted).decode()
        else:
            updates_encoded = ''
        try:
            await self._rb._tc.edit_message(self._message, updates_encoded)
        except MediaCaptionTooLongError:
            raise NoPlaceLeftForMetadata(NoPlaceLeftForMetadata.__doc__) from None
        except ChatAdminRequiredError:
            raise NotEnoughRights(NotEnoughRights.__doc__) from None
        except MessageIdInvalidError as e:
            raise InvalidFile('Can\'t edit caption of this Document') from e
        except MessageNotModifiedError as e:
            logger.debug(
                '''Updates wasn\'t commited to your RemoteBox '''
               f'''because of MessageNotModifiedError: {e}'''
            )

        # Here is Metadata parts that is impossible to change
        restricted_metadata = ('file_size',)

        for k,v in tuple(updates.items()):
            if k in restricted_metadata:
                raise ValueError(f'You can not change "{k}".')

            if k in (*self.__required_metadata, 'efile_path'):
                if k == 'cattrs':
                    self._cattrs.update(PackedAttributes.unpack(v))

                elif k == 'duration':
                    setattr(self, f'_{k}', bytes_to_int(v))

                elif k == 'efile_path':
                    self._file_path = new_file_path
                else:
                    # str attributes
                    if k in ('mime', 'file_name'):
                        setattr(self, f'_{k}', v.decode())
                    else:
                        setattr(self, f'_{k}', v)
            else:
                # Check for keys that we should ignore
                if k not in ('_BFP',):
                    self._residual_metadata[k] = v

        if dlb:
            dlbf = await dlb.get_file(self._id)

        if dlbf:
            await dlbf.refresh_metadata(_updated_metadata=updates_encoded)

    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this file. You should
        use this method if you want to share this
        file with other people.

        Arguments:
            reqkey (``RequestKey``, optional):
                Requester's ``RequestKey``. If isn't specified
                returns ``ImportKey`` of this file without
                encryption, so **ANYONE** with this key
                can decrypt this remote file.
        """
        self.__raise_initialized()

        if reqkey:
            return make_sharekey(self._filekey, self._file_salt, reqkey)

        return make_sharekey(self._filekey)

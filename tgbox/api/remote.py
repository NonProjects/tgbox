"""Module with API functions and classes for RemoteBox."""

from typing import (
    BinaryIO, Union, NoReturn, Callable,
    AsyncGenerator, List, Dict, Optional
)
from pathlib import Path

from os import PathLike

from base64 import (
    urlsafe_b64encode,
    urlsafe_b64decode
)
from asyncio import iscoroutinefunction

from telethon.tl.custom.file import File
from telethon.tl.functions.messages import EditChatAboutRequest

from telethon.errors import (
    ChatAdminRequiredError,
    MediaCaptionTooLongError,
    AuthKeyUnregisteredError,
    FilePartsInvalidError
)
from telethon.tl.functions.channels import (
    CreateChannelRequest, EditPhotoRequest,
    GetFullChannelRequest, DeleteChannelRequest
)
from telethon.tl.types import (
    Channel, Message, PeerChannel
)
from telethon import events

from ..crypto import get_rnd_bytes
from ..crypto import AESwState as AES

from ..keys import (
    make_mainkey, make_sharekey, MainKey,
    ShareKey, ImportKey, FileKey, BaseKey,
    make_filekey, make_requestkey, RequestKey
)
from ..defaults import (
    Limits, PREFIX, DEF_UNK_FOLDER,
    VERBYTE, BOX_IMAGE_PATH, DEF_TGBOX_NAME,
    REMOTEBOX_PREFIX, DEF_NO_FOLDER, DOWNLOAD_PATH
)
from ..fastelethon import upload_file, download_file

from ..errors import (
    NotEnoughRights, NotATgboxFile, IncorrectKey,
    NotInitializedError, RemoteBoxInaccessible,
    LimitExceeded, NotImported, AESError, RemoteFileNotFound,
    NoPlaceLeftForMetadata, SessionUnregistered
)
from ..tools import (
    int_to_bytes, bytes_to_int, SearchFilter, OpenPretender,
    pad_request_size, PackedAttributes, prbg, anext
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
async def make_remotebox(
        tc: TelegramClient,
        box_name: Optional[str] = DEF_TGBOX_NAME,
        rb_prefix: Optional[str] = REMOTEBOX_PREFIX,
        box_image: Optional[Union[PathLike, str]] = BOX_IMAGE_PATH,
        box_salt: Optional[bytes] = None) -> 'EncryptedRemoteBox':
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

        box_salt (``bytes``, optional):
            Random 32 bytes. Will be used in ``MainKey``
            creation. Default is ``crypto.get_rnd_bytes()``.
    """
    if box_salt and len(box_salt) != 32:
        raise ValueError('BoxSalt bytelength != 32')

    box_salt = urlsafe_b64encode(
        box_salt if box_salt else get_rnd_bytes()
    )
    channel_name = rb_prefix + box_name

    channel = (await tc(CreateChannelRequest(
        channel_name, '', megagroup=False))).chats[0]

    if box_image:
        box_image = await tc.upload_file(open(box_image,'rb'))
        await tc(EditPhotoRequest(channel, box_image))

    await tc(EditChatAboutRequest(channel, box_salt.decode()))
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
    if tc: account = tc

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
        self._box_channel_id = box_channel.id

        self._box_salt = None
        # We can't use await in __init__, so
        # you should await get_box_salt firstly.
        self._box_name = None
        # Similar to box_salt, await get_box_name.

        if defaults:
            self._defaults = defaults
        else:
            self._defaults = RemoteBoxDefaults(
                METADATA_MAX = Limits.METADATA_MAX,
                FILE_PATH_MAX = Limits.FILE_PATH_MAX,
                DEF_UNK_FOLDER = DEF_UNK_FOLDER,
                DEF_NO_FOLDER = DEF_NO_FOLDER,
                DOWNLOAD_PATH = DOWNLOAD_PATH
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
    def event(self) -> events.NewMessage:
        """
        Will return ``events.NewMessage`` for
        ``Channel`` of this *RemoteBox*.

        You can use it in Telethon's decorator,
        see *"Events Reference"* in Telethon Docs.
        """
        return events.NewMessage(chats=self.box_channel_id)

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
                this file (tip: you need to import it with ``dlb.import_file``).

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
            key = self._mainkey # pylint: disable=no-member

        if hasattr(self, '_dlb'):
            dlb = self._dlb # pylint: disable=no-member

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
            key = self._mainkey # pylint: disable=no-member

        if hasattr(self, '_dlb'):
            dlb = self._dlb # pylint: disable=no-member

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
                        m, self._tc, cache_preview=cache_preview,
                        defaults=self._defaults).init()
                else:
                    try:
                        rbf = await EncryptedRemoteBoxFile(
                            m, self._tc, cache_preview=cache_preview,
                            defaults=self._defaults).decrypt(
                                key, erase_encrypted_metadata)

                    except Exception as e: # In case of imported file
                        if return_imported_as_erbf and not dlb:
                            rbf = await EncryptedRemoteBoxFile(
                                m, self._tc, cache_preview=cache_preview,
                                defaults=self._defaults).init()

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
                                        m, self._tc, cache_preview=cache_preview,
                                        defaults=self._defaults).init()

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
                                    m, self._tc, cache_preview=cache_preview,
                                    defaults=self._defaults).decrypt(dlb_file._filekey)
                        else:
                            raise e # Unknown Exception
                yield rbf

    async def search_file(
            self,
            sf: SearchFilter,
            mainkey: Optional[MainKey] = None,
            dlb: Optional['DecryptedLocalBox'] = None,
            cache_preview: bool=True) ->\
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

            cache_preview (``bytes``, optional):
                Will cache preview in file object if ``True``.

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
        ids = sf.in_filters['id'][-1] if sf.in_filters['id'] else None

        it_messages = self.files(
            key=mainkey,
            dlb=dlb,
            ids=ids,
            min_id=min_id,
            max_id=max_id,
            reverse=True,
            cache_preview=cache_preview
        )
        sgen = search_generator(
            sf, lb=dlb,
            it_messages=it_messages,
            cache_preview=cache_preview
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
        aes_state = AES(pf.filekey, pf.metadata[-16:])

        oe = OpenPretender(pf.file, aes_state, pf.filesize)
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

        erbf = await EncryptedRemoteBoxFile(
            file_message, self._tc,
            defaults=self._defaults).init()

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
        await self._tc.delete_dialog(self._box_channel)

    async def delete(self) -> None:
        """
        This method **WILL DELETE** *RemoteBox*.

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
        self._erb = erb
        self._tc = erb._tc

        self._box_channel = erb._box_channel
        self._box_channel_id = erb._box_channel_id

        self._box_salt = erb._box_salt
        self._box_name = erb._box_name

        self._dlb = dlb

        if self._dlb:
            self._mainkey = self._dlb._mainkey
            self._defaults = self._dlb._defaults
        else:
            if not key:
                raise ValueError('Must be specified at least key or dlb')

            if isinstance(key, (MainKey, ImportKey)):
                self._mainkey = MainKey(key.key)
            elif isinstance(key, BaseKey):
                self._mainkey = make_mainkey(key, self._box_salt)
            else:
                raise IncorrectKey('key is not Union[MainKey, ImportKey, BaseKey]')

            self._defaults = erb._defaults

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
            self, sended_file: Message,
            tc: TelegramClient,
            cache_preview: bool=True,
            defaults: Optional[Union[DefaultsTableWrapper,
                RemoteBoxDefaults]] = None):
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

            defaults (``DefaultsTableWrapper``, ``RemoteBoxDefaults``):
                Class with a default values/constants we will use.
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
        self._file_salt = None
        self._box_salt = None
        self._version_byte = None
        self._prefix = None
        self._fingerprint = None

        if self._message.fwd_from:
            self._imported = True
        else:
            self._imported = False

        if defaults is None:
            self._defaults = RemoteBoxDefaults(
                METADATA_MAX = Limits.METADATA_MAX,
                FILE_PATH_MAX = Limits.FILE_PATH_MAX,
                DEF_UNK_FOLDER = DEF_UNK_FOLDER,
                DEF_NO_FOLDER = DEF_NO_FOLDER,
                DOWNLOAD_PATH = DOWNLOAD_PATH,
            )
        else:
            self._defaults = defaults

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
    def tc(self) -> TelegramClient:
        """Returns ``TelegramClient``"""
        return self._tc

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
    def box_salt(self) -> Union[bytes, None]:
        """Returns BoxSalt or ``None`` if not initialized"""
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
        if isinstance(self._defaults, DefaultsTableWrapper):
            if not self._defaults.initialized:
                await self._defaults.init()

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
                if metadata_size > self._defaults.METADATA_MAX:
                    raise LimitExceeded(f'{self._defaults.METADATA_MAX=}, {metadata_size=}.')

                # We will also download IV. It's not included
                # in the total metadata bytesize.
                metadata_size += 16
                break

        if metadata_size > self._defaults.METADATA_MAX:
            raise LimitExceeded(f'{metadata_size=} > {self._defaults.METADATA_MAX=}')

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

        if 'file_fingerprint' in parsedm:
            self._fingerprint = parsedm['file_fingerprint']
        else:
            self._fingerprint = b''

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
        self._defaults = erbf._defaults
        self._cache_preview = erbf._cache_preview

        self._box_salt = erbf._box_salt
        self._box_channel_id = erbf._box_channel_id
        self._file_size = erbf._file_size
        self._fingerprint = erbf._fingerprint

        self._upload_time, self._size = erbf._upload_time, None
        self._file_iv, self._file_salt = erbf._file_iv, erbf._file_salt
        self._cattrs, self._file_path = None, None
        self._duration, self._version_byte = None, erbf._version_byte

        self._preview, self._imported = None, erbf._imported
        self._prefix, self._file_pos = erbf._prefix, None

        self._file_file_name = erbf._file_file_name
        self._mime, self._file_name = None, None
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
        """Returns preview bytes or ``b''`` if not initialized."""
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
    def file_name(self) -> Union[str, None]:
        """Returns file name or ``None`` if not initialized."""
        return self._file_name

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
        self._file_name = secret_metadata['file_name'].decode()
        self._cattrs = PackedAttributes.unpack(secret_metadata['cattrs'])
        self._mime = secret_metadata['mime'].decode()

        if self._mainkey:
            self._file_path = AES(self._mainkey).decrypt(
                secret_metadata['efile_path']
            )
            self._file_path = Path(self._file_path.decode())
        else:
            self._file_path = self._defaults.DEF_NO_FOLDER

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
            self, *, outfile: Optional[Union[str, BinaryIO, Path]] = None,
            hide_folder: bool=False, hide_name: bool=False,
            decrypt: bool=True, request_size: int=524288,
            progress_callback: Optional[Callable[[int, int], None]] = None) -> BinaryIO:
        """
        Downloads and saves remote box file to the ``outfile``.

        Arguments:
            oufile (``str``, ``BinaryIO``, ``PathLike``, optional):
                Path-like or File-like object to which file
                will be downloaded. ``self.defaults.DOWNLOAD_PATH`` by default.

                If ``outfile`` has ``.write()`` method then we will use it.

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

        if outfile is None:
            outfile = self._defaults.DOWNLOAD_PATH

        if isinstance(outfile, (str, PathLike)):
            outfile = Path(outfile)
            outfile.mkdir(exist_ok=True)

            path = self._defaults.DEF_UNK_FOLDER if hide_folder else self._file_path
            # The first '/' symbol in '/home/non/' is also path part,
            # so we need to create a folders like / -> home -> non,
            # however, Linux (and i believe all Unix) OS doesn't allow
            # to use a '/' symbol in filename, so instead of / we use
            # a '@' while creating path. You can refer to it as root.
            path = str(self._defaults.DEF_NO_FOLDER if not path else path)
            #
            if path.startswith('/'):
                path = str(Path('@', path.lstrip('/')))
            #
            if hide_name:
                name = prbg(16).hex() + Path(self._file_name).suffix
            else:
                name = self._file_name

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

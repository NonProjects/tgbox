"""Module with API functions and classes for LocalBox."""

from __future__ import annotations
import logging

from typing import (
    BinaryIO, Union, NoReturn, Callable,
    AsyncGenerator, Dict, Optional, List
)
from os.path import getsize
from pathlib import Path

from os import PathLike
from io import BytesIO
from time import time

from inspect import isasyncgen
from asyncio import iscoroutinefunction, gather
from base64 import urlsafe_b64decode, urlsafe_b64encode

from telethon.tl.types import ChannelParticipantsAdmins
from telethon.errors.rpcerrorlist import ChatAdminRequiredError

from filetype import guess as filetype_guess

from ..crypto import (
    AESwState as AES,
    BoxSalt, FileSalt, IV
)
from ..keys import (
    make_filekey, make_requestkey,
    EncryptedMainkey, make_mainkey,
    make_sharekey, make_dirkey,
    make_hmackey, MainKey, RequestKey,
    ShareKey, ImportKey, FileKey,
    BaseKey, DirectoryKey, HMACKey
)
from ..defaults import (
    PREFIX, VERBYTE, DEF_TGBOX_NAME,
    UploadLimits, MINOR_VERSION
)
from ..errors import (
    LimitExceeded, DurationImpossible, NotEnoughRights,
    IncorrectKey, FingerprintExists, NotInitializedError,
    AlreadyImported, RemoteFileNotFound, InUseException,
    AESError, PreviewImpossible, RemoteBoxInaccessible,
    InvalidFile
)
from ..tools import (
    int_to_bytes, bytes_to_int, SearchFilter,
    PackedAttributes, ppart_id_generator, anext,
    get_media_duration, prbg, make_media_preview,
    make_general_path, make_file_fingerprint
)
from .utils import (
    DirectoryRoot, search_generator, PreparedFile,
    TelegramVirtualFile, TelegramClient,
    DefaultsTableWrapper, RemoteBoxDefaults
)
from .db import TgboxDB

__all__ = [
    'make_localbox',
    'get_localbox',
    'clone_remotebox',
    'EncryptedLocalBox',
    'DecryptedLocalBox',
    'EncryptedLocalBoxDirectory',
    'DecryptedLocalBoxDirectory',
    'EncryptedLocalBoxFile',
    'DecryptedLocalBoxFile',
]
logger = logging.getLogger(__name__)

async def make_localbox(
        erb: 'tgbox.api.remote.EncryptedRemoteBox',
        basekey: BaseKey,
        box_name: Optional[str] = None,
        box_path: Optional[Union[PathLike, str]] = None
        ) -> 'DecryptedLocalBox':
    """
    Makes LocalBox

    Arguments:
        erb (``RemoteBox``):
            ``EncryptedRemoteBox``. You will
            recieve it after ``make_remotebox``.

        basekey (``BaseKey``):
            ``BaseKey`` that will be used
            for ``MainKey`` creation.

        box_name (``str``, optional):
            Filename of your LocalBox database. If not
            specified, will be used ``RemoteBox`` name.

        box_path (``PathLike``, ``str``, optional):
            Path in which we will make a database
            file. Current Working Dir if not specified.
    """
    box_name = box_name if box_name else (await erb.get_box_name())
    box_path = Path(box_path if box_path else '.') / box_name

    logger.info(f'TgboxDB.create({box_path})')
    tgbox_db = await TgboxDB.create(box_path)

    if (await tgbox_db.BOX_DATA.count_rows()):
        await tgbox_db.close()

        raise InUseException(
           f'''"{box_path}" file is already exists. '''
            '''Please move old file or create RemoteBox with '''
            '''the different box name (see help(tgbox.api.re'''
            '''mote.make_remotebox) and use kwarg "box_name")'''
        )
    box_salt = await erb.get_box_salt()
    mainkey = make_mainkey(basekey, box_salt)

    logger.debug('tgbox_db.BOX_DATA.insert(...)')

    await tgbox_db.BOX_DATA.insert(
        AES(mainkey).encrypt(int_to_bytes(erb._box_channel_id)),
        AES(mainkey).encrypt(int_to_bytes(int(time()))),
        box_salt.salt,
        None, # We didn't cloned box, so eMainkey is empty
        AES(basekey).encrypt(erb._tc.session.save().encode()),
        AES(mainkey).encrypt(int_to_bytes(erb._tc._api_id)),
        AES(mainkey).encrypt(bytes.fromhex(erb._tc._api_hash)),
        None # FAST_SYNC_LAST_EVENT_ID
    )
    return await EncryptedLocalBox(tgbox_db).decrypt(basekey)

async def get_localbox(
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
        logger.info(f'Getting DecryptedLocalBox of {tgbox_db.db_path}')
        try:
            return await EncryptedLocalBox(tgbox_db).decrypt(basekey)
        except AESError as e:
            await tgbox_db.close()
            raise e
    else:
        logger.info(f'Getting EncryptedLocalBox of {tgbox_db.db_path}')
        return await EncryptedLocalBox(tgbox_db).init()

async def clone_remotebox(
        drb: 'tgbox.api.remote.DecryptedRemoteBox',
        basekey: BaseKey,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        box_name: Optional[str] = None,
        box_path: Optional[Union[PathLike, str]] = None,
        timeout: Optional[int] = 15) -> 'DecryptedLocalBox':
    """
    This method makes ``LocalBox`` from ``RemoteBox`` and
    imports all RemoteBoxFiles to it.

    Arguments:
        drb (``DecryptedRemoteBox``):
            ``DecryptedRemoteBox`` you want to clone.

        basekey (``BaseKey``):
            ``BaseKey`` with which you will decrypt your
            cloned ``EncryptedLocalBox``. ``BaseKey`` encrypts
            Session and ``MainKey`` of original LocalBox.

        progress_callback (``Callable[[int, int], None]``, optional):
            A callback function accepting two parameters:
            (current_amount, total).

        box_name (``str``, optional):
            Filename of your LocalBox database. If not
            specified, will be used ``RemoteBox`` name.

        box_path (``PathLike``, ``str``, optional):
            Path in which we will make a database
            file. Current Working Dir if not specified.

        timeout (``int``, optional):
            How many seconds generator will sleep at every 1000 file.
            By default it's 15 seconds. Don't use too low timeouts or
            you will receive FloodWaitError.
    """
    box_name = box_name if box_name else (await drb.get_box_name())
    box_path = Path(box_path if box_path else '.') / box_name

    # The next async loop will check if it's possible
    # to decrypt first, non-imported RemoteBox file;
    # if not, Phrase->BaseKey->MainKey is incorrect

    no_files_to_import = False
    async for erbf in drb._erb.files():
        if not erbf.imported:
            try:
                await erbf.decrypt(drb._mainkey) # AESError here is OK
            except AESError as e:
                await drb.done()
                raise e
            break # This will omit else statement
    else:
        # RemoteBox doesn't have files to import
        no_files_to_import = True


    logger.info(f'TgboxDB.create({box_path})')
    tgbox_db = await TgboxDB.create(box_path)

    if (await tgbox_db.BOX_DATA.count_rows()):
        await tgbox_db.close()

        raise InUseException(
            f'''TgboxDB file "{box_path}" already exists. Specify new box_path or, '''
            '''if your clone process was interrupted for some reason, '''
            '''use the .sync(..., deep=True) on your LocalBox instead.'''
        )

    logger.info(f'Cloning DecryptedRemoteBox to LocalBox {box_path}')

    last_file_id = await drb.get_last_file_id()
    box_salt = await drb.get_box_salt()

    # We don't need to store encrypted MainKey if user
    # clone RemoteBox with it's natural BaseKey.
    if make_mainkey(basekey, box_salt) == drb._mainkey:
        emainkey = None # We can make MainKey with BaseKey
    else:
        # We need to store encrypted MainKey
        emainkey = AES(basekey).encrypt(drb._mainkey.key)

    await tgbox_db.BOX_DATA.insert(
        AES(drb._mainkey).encrypt(int_to_bytes(drb._box_channel_id)),
        AES(drb._mainkey).encrypt(int_to_bytes(int(time()))),
        box_salt.salt,
        emainkey,
        AES(basekey).encrypt(drb._tc.session.save().encode()),
        AES(drb._mainkey).encrypt(int_to_bytes(drb._tc._api_id)),
        AES(drb._mainkey).encrypt(bytes.fromhex(drb._tc._api_hash)),
        None # FAST_SYNC_LAST_EVENT_ID
    )
    dlb = await EncryptedLocalBox(tgbox_db).decrypt(basekey)

    if no_files_to_import:
        return dlb # RemoteBox is empty

    files_generator = drb.files(
        timeout=timeout,
        erase_encrypted_metadata=False
    )
    drbf_to_import, IMPORT_WHEN = [], 100
    try:
        async for drbf in files_generator:
            if progress_callback:
                if iscoroutinefunction(progress_callback):
                    await progress_callback(drbf.id, last_file_id)
                else:
                    progress_callback(drbf.id, last_file_id)

            logger.debug(f'Adding ID{drbf.id} from RemoteBox ID{drb.box_channel_id} to import list')
            drbf_to_import.append(dlb.import_file(drbf))

            if len(drbf_to_import) == IMPORT_WHEN:
                logger.debug(f'Importing new stack of files [{len(drbf_to_import)}]')
                await gather(*drbf_to_import)
                drbf_to_import.clear()

        if drbf_to_import:
            logger.debug(f'Importing remainder of files [{len(drbf_to_import)}]')
            await gather(*drbf_to_import)

        # If user provided incorrect decryption key, the files_generator
        # will make a zero iterations, so DecryptedLocalBox will be empty
        if last_file_id and not (await dlb.get_last_file_id()):
            raise AESError('No file was imported. Incorrect Key?')

        return dlb
    except Exception as e:
        await dlb.done()
        raise e

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

    You can access it from the ``DecryptedLocalBox``:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_localbox
        from tgbox.keys import make_basekey, Phrase

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_localbox(basekey)
            # Retrieve encrypted session
            print(dlb._elb.session)

        asyncio_run(main())
    """
    def __init__(
            self, tgbox_db: TgboxDB,
            defaults: Optional[Union[DefaultsTableWrapper,
                RemoteBoxDefaults]] = None):
        """
        Arguments:
            tgbox_db (``TgboxDB``):
                Initialized Tgbox Database.

            defaults (``DefaultsTableWrapper``, ``RemoteBoxDefaults``):
                Class with a default values/constants we will use.
        """
        self._tgbox_db = tgbox_db

        if defaults is None:
            logger.debug('Custom defaults is not present')
            self._defaults = DefaultsTableWrapper(self._tgbox_db)
        else:
            logger.debug('Found custom defaults, will try to use it')
            self._defaults = defaults

        self._api_id = None
        self._api_hash = None

        self._mainkey = None
        self._box_salt = None
        self._session = None

        self._box_channel_id = None
        self._box_cr_time = None

        self._fast_sync_last_event_id = None

        self._initialized = False
        self._is_encrypted = True

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({repr(self._tgbox_db)}, {repr(self._defaults)})'

    def __str__(self) -> str:
        box_salt = None if not self._initialized else urlsafe_b64encode(self.box_salt.salt).decode()
        return (
            f'''{self.__class__.__name__}({repr(self._tgbox_db)}, {repr(self._defaults)}) '''
            f'''# {self._initialized=}, {self._box_channel_id=}, {box_salt=}'''
        )
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
    def is_encrypted(self) -> bool:
        """
        Will return ``True`` if this is an *Encrypted*
        class, ``False`` if *Decrypted*
        """
        return self._is_encrypted

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
    def defaults(self) -> Union[DefaultsTableWrapper, RemoteBoxDefaults]:
        """Returns ``DefaultsTableWrapper`` or ``RemoteBoxDefaults``."""
        return self._defaults

    @property
    def initialized(self) -> bool:
        """Returns ``True`` if you called ``.init()``"""
        return self._initialized

    @property
    def box_salt(self) -> Union[BoxSalt, None]:
        """Returns ``BoxSalt`` or ``None`` if not initialized"""
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

    async def remove_empty_directories(self, part_ids: Optional[List[bytes]] = None):
        """
        By default, the *Protocol* will **not** automatically remove
        empty *Directories* after the file deletion process was done
        (unless forced). To do this, use this method.

        Arguments:
            part_ids (``List[bytes]``, optional):
                List of *Part ID* you want to check. Will remove
                only if *Directory* attached to this *Part ID*
                is orphaned (no files/other *Directories* linked)

                If not specified, will check every *Part ID* in *LocalBox*.
        """
        if not part_ids:
            logger.debug('part_ids is not specified, making a full check...')

            part_ids = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT PART_ID FROM PATH_PARTS', ()
            ))
            part_ids = [pid[0] for pid in await part_ids.fetchall()]

        for ppath_head in part_ids:
            # The code below will check all parent path part ids
            # and remove empty ones (which doesn't pointed)
            while True:
                delete_ppath_head = True

                # Retrieve file rows that point to PPATH_HEAD
                files_pointed = await self._tgbox_db.FILES.execute((
                    'SELECT ID FROM FILES WHERE PPATH_HEAD=?',
                    (ppath_head,)
                ))
                if (await files_pointed.fetchone()):
                    delete_ppath_head = False # Part ID pointed by file

                # Amount of parts that point to current ppath_head
                pparts_pointed = await self._tgbox_db.PATH_PARTS.execute((
                    'SELECT * FROM PATH_PARTS WHERE PARENT_PART_ID=?',
                    (ppath_head,)
                ))
                if (await pparts_pointed.fetchone()):
                    delete_ppath_head = False

                if delete_ppath_head:
                    logger.debug(
                        '''Removing orphaned directory | DELETE FROM '''
                       f'''PATH_PARTS WHERE PART_ID={ppath_head}'''
                    )
                    await self._tgbox_db.PATH_PARTS.execute((
                        'DELETE FROM PATH_PARTS WHERE PART_ID=?',
                        (ppath_head,)
                    ))
                parent_part_id = await self._tgbox_db.PATH_PARTS.execute(
                    sql_tuple=(
                        'SELECT PARENT_PART_ID FROM PATH_PARTS WHERE PART_ID=?',
                        (ppath_head,)
                    )
                )
                # Set parent part id as ppath_head to recursive
                # check for useless path parts
                ppath_head = await parent_part_id.fetchone()
                ppath_head = ppath_head[0] if ppath_head else None

                if not ppath_head:
                    break

    async def get_files_total(self) -> int:
        """Returns a total number of files in this LocalBox"""
        return await self._tgbox_db.FILES.count_rows()

    async def init(self) -> 'EncryptedLocalBox':
        """Will fetch and parse data from Database."""
        logger.debug('EncryptedLocalBox initialization...')

        if not self._tgbox_db.initialized:
            await self._tgbox_db.init()

        if not await self._tgbox_db.BOX_DATA.count_rows():
            raise NotInitializedError('Table is empty.')
        else:
            box_data = await self._tgbox_db.BOX_DATA.select_once()
            self._box_channel_id = box_data[0]
            self._box_cr_time, self._box_salt, self._mainkey = box_data[1:4]
            self._session, self._initialized = box_data[4], True
            self._api_id, self._api_hash = box_data[5], box_data[6]
            self._fast_sync_last_event_id = box_data[7]

            self._box_salt = BoxSalt(self._box_salt)

            if self._mainkey:
                logger.debug('Found EncryptedMainkey')
                self._mainkey = EncryptedMainkey(self._mainkey)

            if isinstance(self._defaults, DefaultsTableWrapper):
                logger.debug('Custom defaults is NOT used')
                if not self._defaults.initialized:
                    await self._defaults.init()
            else:
                logger.debug('Custom defaults IS used')

        return self

    async def get_file(
            self,
            id: Optional[int] = None,
            fingerprint: Optional[bytes] = None,
            decrypt: Optional[bool] = None,
            cache_preview: bool=True,
            erase_encrypted_metadata: bool=True) -> Union[
                'DecryptedLocalBoxFile',
                'EncryptedLocalBoxFile', None]:
        """
        Returns ``EncryptedLocalBoxFile`` from ``EncryptedLocalBox``
        or ``DecryptedLocalBoxFile`` from ``DecryptedLocalBox`` if
        file exists. ``None`` otherwise.

        Arguments:
            id (``int``, optional):
                File ID. Must be specified if
                ``fingerprint`` is ``None``.

            fingerprint (``bytes``, optional):
                File Fingerprint. Must be specified
                if ``id`` argument is ``None``.

            decrypt (``bool``, optional):
                Will return ``EncryptedLocalBoxFile`` if ``False``,
                and ``DecryptedLocalBoxFile`` if ``True``. If
                ``None``, will be determined by class.

            cache_preview (``bool``, optional):
                Cache preview in class or not.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedLocalBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        if not any((id is not None, fingerprint)):
            raise ValueError('At least `id` or `fingerprint` must be specified.')

        if fingerprint:
            logger.info(f'Trying to fetch ID of file with {fingerprint=}...')
            try:
                # Get ID of local file by its fingerprint (if exists)
                id = await self._tgbox_db.FILES.select_once(sql_tuple=
                    ('SELECT ID FROM FILES WHERE FINGERPRINT=?', (fingerprint,))
                )
                id = id[0]
            except StopAsyncIteration:
                return None
        try:
            self.__raise_initialized()
            logger.info(f'File by ID{id} was requested from LocalBox')

            if decrypt is None and isinstance(self, DecryptedLocalBox):
                decrypt = True

            elif decrypt is None and isinstance(self, EncryptedLocalBox):
                decrypt = False

            if decrypt and self._mainkey and not\
                isinstance(self._mainkey, EncryptedMainkey):
                    logger.debug(f'Trying to return ID{id} DecryptedLocalBoxFile...')

                    elbf = EncryptedLocalBoxFile(id, self._elb, # pylint: disable=E1101
                        cache_preview=cache_preview
                    )
                    return await elbf.decrypt(dlb=self,
                        erase_encrypted_metadata=erase_encrypted_metadata)
            else:
                logger.debug(f'Trying to return ID{id} EncryptedLocalBoxFile...')

                elbf = EncryptedLocalBoxFile(id, self,
                    cache_preview=cache_preview)
                return await elbf.init()

        except StopAsyncIteration: # There is no file by "id" in the *LocalBox.
            logger.debug(f'LocalBox doesn\'t have a file with ID{id}: return None.')
            return None

    async def contents(
            self, sfpid: Optional[bytes] = None,
            ignore_files: Optional[bool] = False,
            erase_encrypted_metadata: Optional[bool] = True
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
                Will **not** return LocalBoxFile associated
                with the *LocalBoxDirectory* if ``False``.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedLocalBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        sfpid = (sfpid,) if sfpid else []

        if not sfpid:
            root_pids = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT PART_ID FROM PATH_PARTS WHERE PARENT_PART_ID IS NULL', ()
            ))
            sfpid = [i[0] for i in await root_pids.fetchall()]

        logger.info(f'*LocalBox.contents(), {sfpid=}')

        for pid in sfpid:
            if isinstance(self, DecryptedLocalBox):
                lbfid = EncryptedLocalBoxDirectory(self._elb, pid)
                lbfid = await lbfid.decrypt(dlb=self)
            else:
                lbfid = EncryptedLocalBoxDirectory(self, pid)
                lbfid = await lbfid.init()

            yield lbfid

            if not ignore_files:
                _iterdir = lbfid.iterdir(
                    ignore_dirs=True,
                    erase_encrypted_metadata=erase_encrypted_metadata
                )
                async for lbfi in _iterdir:
                    yield lbfi

            child_pids = await self._tgbox_db.PATH_PARTS.execute((
                'SELECT PART_ID FROM PATH_PARTS WHERE PARENT_PART_ID IS ?',
                (pid,)
            ))
            child_sfpid = [i[0] for i in await child_pids.fetchall()]

            # ---------------------------------------------------------- #
            # We need to wrap 'contents' method here if it was syncified,
            # otherwise we will 'async for' on sync generator

            for csfpid in child_sfpid:
                contents = self.contents(csfpid,
                    ignore_files=ignore_files,
                    erase_encrypted_metadata=erase_encrypted_metadata
                )
                if not isasyncgen(contents): # Was syncified
                    async def _async_iter_from(_iter_from):
                        try:
                            while True:
                                yield await next(_iter_from)
                        except StopAsyncIteration:
                            return

                    contents = _async_iter_from(contents)

                async for content in contents:
                    yield content

            # ---------------------------------------------------------- #

    async def files(
            self, cache_preview: bool=True,
            min_id: Optional[int] = None,
            max_id: Optional[int] = None,
            ids: Optional[int, list] = None,
            decrypt: Optional[bool] = None,
            reverse: Optional[bool] = False,
            fetch_count: Optional[int] = 100,
            erase_encrypted_metadata: Optional[bool] = True)\
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

            min_id (``int``, optional):
                Will iterate from this ID.

            max_id (``int``, optional):
                Will iterate up to this ID.

            ids (``int``, ``list``, optional):
                ID or list with IDs you want to
                fetch. If specified, The min_id
                and max_id args will be ignored

            decrypt (``bool``, optional):
                Will return ``EncryptedLocalBoxFile`` if ``False``,
                and ``DecryptedLocalBoxFile`` if ``True``. If
                ``None``, will be determined by class.

            reverse (``bool``, optional):
                If set to ``True``, the local files will be returned in reverse
                order (from newest to oldest, instead of the default oldest
                to newest).

            fetch_count (``int``, optional):
                Amount of files generator will fetch and cache from
                SQLite table before return. ``100`` by default.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedLocalBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        assert fetch_count > 0, 'fetch_count must be > 0'

        if ids:
            ids = str(tuple(ids)) if len(ids) > 1 else f'({ids[0]})'
            sql_query = f'SELECT ID FROM FILES WHERE ID IN {ids}'
        else:
            min_id = f'ID >= {min_id}' if min_id else ''
            max_id = f'ID <= {max_id}' if max_id else ''

            min_id = min_id + ' AND' if all((min_id, max_id)) else min_id
            where = 'WHERE' if any((min_id, max_id)) else ''

            sql_query = f'SELECT ID FROM FILES {where} {min_id} {max_id} '

        order = 'DESC' if reverse else 'ASC'
        sql_query += f'ORDER BY ID {order}'

        logger.debug(sql_query)
        cursor = await self._tgbox_db.FILES.execute((sql_query ,()))

        while True:
            logger.debug(f'Trying to fetch new portion of local files ({fetch_count})...')

            pending = await cursor.fetchmany(fetch_count)
            if not pending: return # No more files

            pending = [
                self.get_file(
                    file_id[0], decrypt=decrypt,
                    cache_preview=cache_preview,
                    erase_encrypted_metadata=erase_encrypted_metadata
                )
                for file_id in pending
            ]
            pending = await gather(*pending)

            while pending:
                yield pending.pop(0)

    async def delete_files(
            self,

            *lbf: Union[
                'EncryptedLocalBoxFile',
                'DecryptedLocalBoxFile'
            ],
            lbf_ids: Optional[list] = None,

            rb: Optional[
                Union[
                    'tgbox.api.remote.EncryptedRemoteBox',
                    'tgbox.api.remote.DecryptedRemoteBox'
                ]
            ] = None,
            remove_empty_directories: Optional[bool] = False) -> None:
        """
        A function to remove a bunch of local files at once.

        Arguments:
            lbf (``EncryptedLocalBoxFile``, ``DecryptedLocalBoxFile``, asterisk):
                ``(Encrypted|Decrypted)LocalBoxFile(s)`` to remove.

            lbf_ids (``list``, optional):
                You can specify ids instead of LocalBox file
                objects. However, ``lbf`` is preferred here.

            rb (``EncryptedRemoteBox``, ``DecryptedRemoteBox``, optional):
                You can specify a *RemoteBox* associated
                with current *LocalBox* to also remove
                all specified files in *RemoteBox* too.

            remove_empty_directories (``bool``, optional):
                If ``True``, will remove orphaned directories
                that left after removing files (if any).

                Alternative: ``dlb.remove_empty_directories()``

        .. note::
            Without ``rb`` this will delete files only from
            your LocalBox. To completly remove your file
            use the same coroutine on *RemoteBox* or
            specify ``(Encrypted|Decrypted)RemoteBox``.
        """
        lbf_ids = lbf_ids if lbf_ids else []
        lbf_ids.extend(lbf_.id for lbf_ in lbf)

        logger.info(f'Removing {len(lbf_ids)} local files...')

        q = '(' + ('?,' * len(lbf_ids))[:-1] + ')'

        await self._tgbox_db.FILES.execute(sql_tuple=(
            f'DELETE FROM FILES WHERE ID IN {q}', lbf_ids
        ))
        part_ids = set(lbf_.directory.part_id for lbf_ in lbf) if lbf else []

        if remove_empty_directories:
            await self.remove_empty_directories(part_ids=part_ids)

        if rb:
            await rb.delete_files(rbf_ids=lbf_ids)

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
        return make_requestkey(basekey, self._box_salt)

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

        logger.info(f'Removing LocalBox {self._tgbox_db.db_path}...')
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
        logger.info('Closing all LocalBox DB connections...')
        try:
            await self._tgbox_db.close()
        except ValueError as e:
            # Most probably this is because of LocalBox.delete(),
            # so this message will go to DEBUG, no higher
            logger.debug(f'Failed to done() due {e}')

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
        from tgbox.api import get_localbox, DecryptedLocalBoxFile
        from tgbox.keys import make_basekey, Phrase

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_localbox(basekey)

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
        self._defaults = elb._defaults

        self._is_encrypted = False
        self._initialized = True

        if isinstance(key, BaseKey):
            logger.debug('BaseKey specified as key')
            if isinstance(elb._mainkey, EncryptedMainkey):
                logger.debug('Found EncryptedMainkey, decrypting...')
                try:
                    mainkey = AES(key).decrypt(elb._mainkey.key)
                except ValueError: # invalid padding byte
                    raise AESError('Can\'t decrypt eMainKey. Incorrect Key?')
                self._mainkey = MainKey(mainkey)
            else:
                self._mainkey = make_mainkey(key, self._elb._box_salt)
            try:
                # We encrypt Session with Basekey to prevent stealing
                # Session information by people who also have mainkey
                # of the same box. So there is decryption with basekey.
                self._session = AES(key).decrypt(elb._session).decode()
            except (UnicodeDecodeError, ValueError):
                raise AESError ('Can\'t decrypt Session. Invalid Basekey?')

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
        self._api_hash = AES(self._mainkey).decrypt(elb._api_hash).hex()
        self._box_salt = elb._box_salt

        self._fast_sync_last_event_id = elb._fast_sync_last_event_id

        if self._fast_sync_last_event_id:
            self._fast_sync_last_event_id = bytes_to_int(
                AES(self._mainkey).decrypt(self._fast_sync_last_event_id)
            )

    @property
    def mainkey(self) -> MainKey:
        """Will return ``MainKey`` of this *Box*"""
        return self._mainkey

    @staticmethod
    async def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBox`` """
            """and cannot be used on ``DecryptedLocalBox``."""
        )
    @staticmethod
    async def decrypt() -> NoReturn:
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
        file_path = make_general_path(file_path)
        ppidg = ppart_id_generator(file_path, self._mainkey)

        for part, parent_part_id, part_id in ppidg:
            if not parent_part_id:
                parent_part_id = None

            logger.debug(
               f'''Adding ({part}, {parent_part_id}, {part_id}) '''
                '''to the PATH_PARTS if it\'s not already in'''
            )
            sql_query = (
                'INSERT OR IGNORE INTO PATH_PARTS VALUES (?,?,?)',
                (AES(self._mainkey).encrypt(part.encode()),
                part_id, parent_part_id)
            )
            await self._tgbox_db.PATH_PARTS.execute(sql_query)

        elbd = EncryptedLocalBoxDirectory(self._elb, part_id)
        return await elbd.decrypt(dlb=self)

    async def _make_local_file(
            self, pf: 'PreparedFile',
            update: Optional[bool] = None) -> 'DecryptedLocalBoxFile':
        """
        Creates a LocalBoxFile.

        Arguments:
            pf (``PreparedFile``):
                Pushed to RemoteBox ``PreparedFile``.

            update (``bool``, optional):
                If ``True``, will change local file with
                the information from ``pf``.
        """
        assert hasattr(pf,'file_id'), 'Push to RemoteBox firstly'
        assert hasattr(pf,'upload_time'), 'Push to RemoteBox firstly'
        try:
            # Verify that there is no file with the same ID
            await self._tgbox_db.FILES.select_once(
                sql_tuple=('SELECT ID FROM FILES WHERE ID=?', (pf.file_id,))
            )
        except StopAsyncIteration:
            pass
        else:
            if update:
                logger.info(f'Updating LocalBox file ID{pf.file_id}...')
                await self.delete_files(lbf_ids=[pf.file_id])
            else:
                raise AlreadyImported('There is already file with same ID') from None

        eupload_time = AES(pf.filekey).encrypt(int_to_bytes(pf.upload_time))

        if pf.imported:
            logger.info(f'Adding imported PreparedFile ID{pf.file_id} to LocalBox')

            packed_metadata_pos = len(PREFIX) + len(VERBYTE) + 3
            unpacked_metadata = pf.metadata[packed_metadata_pos:-16] # -16 is IV
            file_box_salt = PackedAttributes.unpack(unpacked_metadata)['box_salt']

            if file_box_salt == self.box_salt.salt:
                logger.debug('We can make FileKey, eFileKey WILL be None.')
                efilekey = None # We can make it with our (Main/Dir)Key
            else:
                logger.debug('We can\'t make FileKey, eFileKey will NOT be None.')
                efilekey = AES(self._mainkey).encrypt(pf.filekey.key)
        else:
            logger.info(f'Adding PreparedFile ID{pf.file_id} to LocalBox')
            efilekey = None

        logger.debug('Making LocalBox path parts from PreparedFile file path...')
        part_id = (await self._make_local_path(pf.filepath)).part_id

        updated_metadata = getattr(pf, 'updated_enc_metadata', None)
        try:
            await self._tgbox_db.FILES.insert(
                pf.file_id, eupload_time,
                part_id, efilekey, pf.fingerprint,
                pf.metadata, updated_metadata
            )
        except Exception as e:
            raise AlreadyImported(
               f'Can not import File ID{pf.file_id}. Already '
                'exist in LocalBox. Consider remove firstly.') from e

        elbf = EncryptedLocalBoxFile(pf.file_id, self._elb)
        return await elbf.decrypt(dlb=self)

    async def _check_fingerprint(self, fingerprint: bytes):
        """
        Will check that file path is unique, and if not
        then will raise a ``FingerprintExists`` error.

        This is mostly for internal use.

        Arguments:
            fingerprint (``bytes``):
                BoxFile fingerprint.
        """
        try:
            # Verify that there is no file with the same fingerprint
            id = await self._tgbox_db.FILES.select_once(sql_tuple=(
                'SELECT ID FROM FILES WHERE FINGERPRINT=?',
                (fingerprint,)
            ))
        except StopAsyncIteration:
            pass
        else:
            error_msg = (
                f'''{FingerprintExists.__doc__} (ID={id[0]}). If you '''
                 '''want to UPDATE file, set skip_fingerprint_check=True'''
            )
            raise FingerprintExists(error_msg) from None

    async def _merge_um_then_refresh(self, dlbf, drbf):
        """
        This local function will update Metadata Updates
        of LocalBox file from the Metadata Updates of
        the RemoteBox file (if any), preserving local
        CAttrs and other changes in local Metadata
        """
        try:
            rbf_um = urlsafe_b64decode(drbf._message.message)
            rbf_um = AES(drbf._filekey).decrypt(rbf_um)
            rbf_um = PackedAttributes.unpack(rbf_um)
        except Exception as e:
            logger.debug(
                'Can not store Metadata Updates from RemoteBox '
               f'file ID{dlbf.id} due to {e}'); return

        if dlbf.cattrs:
            # This part will preserve Local CAttrs (if any)
            if cattrs := rbf_um.get('cattrs', {}):
                cattrs = PackedAttributes.unpack(cattrs)

            rbf_um['cattrs'] = PackedAttributes.pack(**(cattrs | dlbf.cattrs))

        # ------------------------------------------------------------- #
        # This part will merge Local Metadata Updates with Remote Updates

        if dlbf._updated_metadata:
            lbf_um = AES(dlbf._filekey).decrypt(dlbf._updated_metadata)
            lbf_um = PackedAttributes.unpack(lbf_um) | rbf_um
        else:
            lbf_um = rbf_um # LocalBox file doesn't have Updated Metadata

        # ------------------------------------------------------------- #

        lbf_um = AES(dlbf._filekey).encrypt(PackedAttributes.pack(**lbf_um))
        logger.debug(f'Refreshing Metadata of LocalBox file ID{dlbf.id}')
        await dlbf.refresh_metadata(_updated_metadata=lbf_um)

    async def _fast_sync(
            self, drb: 'tgbox.api.remote.DecryptedRemoteBox',
            progress_callback: Optional[Callable[[int, str], None]] = None):
        """
        This method will make a fast synchronization of
        your LocalBox with the RemoteBox. See help on
        DecryptedLocalBox.sync method for more info.

        drb (``DecryptedRemoteBox``):
            *RemoteBox* associated with this LocalBox.

        progress_callback (``Callable[[int, str], None]``, optional):
            A callback function accepting two
            parameters: (file_id, action<str>).

            Don't treat this as progressbar. The code
            will call/await the specified callback
            with one of the arguments from below:
                * ``fast_progress_callback(22, 'deleted')`` OR
                * ``fast_progress_callback(22, 'updated')`` OR
                * ``fast_progress_callback(22, 'imported')`` OR
                * ``fast_progress_callback(22, 'metadata updated')``
        """
        drb_box_name = await drb.get_box_name()
        logger.info(f'Fast syncing {self._tgbox_db.db_path} with {drb_box_name}...')

        try:
            box_admins = await drb.tc.get_participants(
                entity = drb.box_channel,
                filter = ChannelParticipantsAdmins
            )
        except ChatAdminRequiredError as e:
            err_msg = (
                """You don't have enough rights (access to Admin Log) """
                """to make a fast box synchronization. Ask a RemoteBox """
                """owner to make You (at least) Admin with 0 rights or """
                """use a deep syncing by specifying "deep" flag. Specify """
                """"start_from" ID to fasten deep syncing."""
            )
            raise NotEnoughRights(err_msg) from e

        box_admins = [admin.id for admin in box_admins]
        box_admins.remove((await drb.tc.get_entity('me')).id)

        if not box_admins:
            logger.debug('No Admins except You found. Fast sync ignored.')
            return

        last_event_id = None

        id_to_update = []
        id_to_remove = []

        IMPORT_WHEN = 100

        async def import_update_file(event):
            # This function will Import or Update
            # Local file or Update Metadata of File
            drbf = await drb.get_file(event.old.id,
                erase_encrypted_metadata=False
            )
            if drbf is None:
                return

            action = None
            try:
                logger.debug(f'Trying to import ID{event.old.id}...')
                await self.import_file(drbf)
                action = 'imported'

            except AlreadyImported:
                if event.old.file.name != event.new.file.name:
                    logger.debug(f'Updating file ID{drbf.id}...')
                    await self.delete_files(lbf_ids=[drbf.id])
                    try:
                        dlbf = await self.import_file(drbf)
                    except AlreadyImported:
                        logger.debug(f'Can not import ID{drbf.id}. Skipping.')
                        return

                    await self._merge_um_then_refresh(dlbf, drbf)

                    action = 'updated'
                else:
                    logger.debug(
                       f'''ID{drbf.id} is already imported. '''
                        '''Checking for updated metadata...'''
                    )
                    action = 'metadata updated'

                    dlbf = await self.get_file(drbf.id,
                        erase_encrypted_metadata=False
                    )
                    if not dlbf:
                        return

                    await self._merge_um_then_refresh(dlbf, drbf)

            if progress_callback:
                if iscoroutinefunction(progress_callback):
                    await progress_callback(drbf.id, action)
                else:
                    progress_callback(drbf.id, action)


        admin_log_gen = drb.tc.iter_admin_log(
            entity = drb.box_channel,
            delete=True, edit=True,
            admins = box_admins
        )
        async for event in admin_log_gen:
            # We can ignore here 'id_to_remove' as we will remove
            # all target files after imports/updates would be done
            if len(id_to_update) >= IMPORT_WHEN:
                await gather(*id_to_update)
                id_to_update.clear()

            if event.id == self._fast_sync_last_event_id:
                break # Already checked all IDs

            elif last_event_id is None:
                last_event_id = event.id

            if event.deleted_message:
                id_to_remove.append(event.old.id)

            elif event.changed_message:
                id_to_update.append(import_update_file(event))


        id_to_update.append(self.delete_files(lbf_ids=id_to_remove))
        await gather(*id_to_update) # Gather reminder + id_to_remove

        if progress_callback:
            pc_list = []
            for id in id_to_remove:
                if iscoroutinefunction(progress_callback):
                    pc_list.append(progress_callback(id, 'deleted'))
                else:
                    progress_callback(id, 'deleted')

            await gather(*pc_list)


        if last_event_id and self._fast_sync_last_event_id != last_event_id:
            self._fast_sync_last_event_id = last_event_id

            last_event_id = AES(self._mainkey).encrypt(
                int_to_bytes(last_event_id)
            )
            logger.debug(
                '''UPDATE BOX_DATA SET FAST_SYNC_'''
               f'''LAST_EVENT_ID={last_event_id}'''
            )
            await self._tgbox_db.BOX_DATA.execute((
                'UPDATE BOX_DATA SET FAST_SYNC_LAST_EVENT_ID=?',
                (last_event_id,)
            ))

    async def _deep_sync(
            self, drb: 'tgbox.api.remote.DecryptedRemoteBox',
            start_from: Optional[int] = None,
            progress_callback: Optional[Callable[[int, int], None]] = None,
            timeout: Optional[int] = 15):
        """
        This method will make a deep synchronization of
        your LocalBox with the RemoteBox. See help on
        DecryptedLocalBox.sync method for more info.

        drb (``DecryptedRemoteBox``):
            *RemoteBox* associated with this *LocalBox*.

        start_from (``int``, optional):
            Will check files that > start_from [ID].

        progress_callback (``Callable[[int, int], None]``, optional):
            A callback function accepting two
            parameters: (current_id, last_id).

        timeout (``int``, optional):
            How many seconds generator will sleep at every 1000 file.
            By default it's 15 seconds. Don't use too low timeouts or
            you will receive FloodWaitError.
        """
        drb_box_name = await drb.get_box_name()
        logger.info(f'Deep syncing {self._tgbox_db.db_path} with {drb_box_name}...')

        # This will yield the first uploaded to RemoteBox file
        first_drbf = await anext(drb.files(), None)

        if not first_drbf:
            logging.debug(f'RemoteBox {drb_box_name} is empty. Clearing local...')

            await self._tgbox_db.FILES.execute(
                sql_tuple=('DELETE FROM FILES', ()))
            await self._tgbox_db.PATH_PARTS.execute(
                sql_tuple=('DELETE FROM PATH_PARTS', ()))
            return

        # This will yield the last uploaded to RemoteBox file
        last_drbf = await anext(drb.files(reverse=True))

        logger.debug(
            '''Removing all files from LocalBox which ID is less '''
            '''than the first RemoteBox file...'''
        )
        await self._tgbox_db.FILES.execute(sql_tuple=(
            'DELETE FROM FILES WHERE ID < ?',
            (first_drbf.id,)
        ))

        drbf_generator = drb.files(
            dlb=self,
            min_id=start_from,
            cache_preview=False,
            return_imported_as_erbf=True,
            timeout=timeout,
            erase_encrypted_metadata=False
        )
        # This is drbf2 from the previous loop cycle
        previous_drbf2 = None

        # We will stack here files to import
        drbf_to_import, IMPORT_WHEN = [], 100

        dlbf_to_update = []

        async def import_stack(stack: list):
            logger.debug(f'Importing new stack of files [{len(stack)}]')
            await gather(*stack); stack.clear()

        async def re_import(drbf):
            # We will use this coroutine to remove already
            # saved file from Local and import it again
            await self.delete_files(lbf_ids=[drbf.id])
            await self.import_file(drbf)

        async def update_after_import(drbfx, dlb, elbfx):
            # Will update Metadata Updates of LocalBox
            # file (if any) with Metadata Updates of
            # RemoteBox file (if any presented)
            if elbfx:
                dlbf = await elbfx.decrypt(dlb=dlb)
            else:
                dlbf = await dlb.get_file(drbfx.id)

            await self._merge_um_then_refresh(dlbf, drbfx)

        while True:
            if len(drbf_to_import) >= IMPORT_WHEN:
                await import_stack(drbf_to_import)

            drbf1 = await anext(drbf_generator, None)
            drbf2 = await anext(drbf_generator, None)

            if not any((drbf1, drbf2)):
                # previous_drbf2 will be None only if
                # we're at the first loop cycle. If
                # drbf1 & drbf2 is None too, then
                # "start_from" arg is incorrect
                if not previous_drbf2:
                    raise RemoteFileNotFound(
                        '''Can not init sync() with start_from='''
                       f'''{start_from}: message doesn\'t exists '''
                       '''or "start_from" equals last file id.'''
                    )
                sql_tuple = ('DELETE FROM FILES WHERE ID > ?', (previous_drbf2.id,))
                logger.debug(f'self._tgbox_db.FILES.execute(sql_tuple={sql_tuple})')

                await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)
                break

            if progress_callback:
                progress = drbf2.id if drbf2 else last_drbf.id

                if iscoroutinefunction(progress_callback):
                    await progress_callback(progress, last_drbf.id)
                else:
                    progress_callback(progress, last_drbf.id)

            for drbfx in (drbf1, drbf2):
                # We check here does file with the same ID is
                # exists in LocalBox (already imported) or not
                if drbfx and not (elbfx := await self._elb.get_file(drbfx.id)):
                    # If not, we check if drbfx is actually an
                    # EncryptedRemoteBoxFile (it can be such if
                    # LocalBox doesn't have FileKey to it,
                    # probably because file is from other remote)
                    if hasattr(drbfx, '_filekey'):
                        # We import file if it's DecryptedRemoteBoxFile,
                        # EncryptedRemoteBoxFile doesn't have _filekey
                        logger.debug(f'Caching import ID{drbfx.id} from {drb_box_name}')
                        drbf_to_import.append(self.import_file(drbfx))
                    else:
                        logger.debug(
                            '''We don\'t have a FileKey to ID'''
                           f'''{drbfx.id}. Skipping.'''
                        )
                elif all((drbfx, elbfx)) and elbfx.file_salt != drbfx.file_salt:
                    # File was updated (re-uploaded) so we should
                    # remove old local file and re-import new
                    logger.debug(f'Caching import of updated ID{drbfx.id} from {drb_box_name}')
                    drbf_to_import.append(re_import(drbfx))

                # If drbfx._message has '.message' (caption), -- it means that
                # RemoteBox file stores Updated Metadata in it. Then, if there
                # is NO elbfx (no LocalBox file, == RemoteBox file NOT imported)
                # we will just save 'drbfx._message.message' b64-decoded string
                # in the 'UPDATED_METADATA' field of the LocalBox file. However,
                # if there IS elbfx (RemoteBox file is already imported) and
                # LocalBox file already has something in 'UPDATED_METADATA',
                # then we will *extend* & preserve Metadata Updates in LocalBox
                if drbfx and drbfx._message.message: # _message.message is caption
                    dlbf_to_update.append(update_after_import(drbfx, self, elbfx))

            # Here we will remove all local files which ID is between
            # the previous_drbf2.id <...X...> drbf1.id and also
            # between the drbf1.id <...X...> drbf2.id
            for pair in (pairs := ((previous_drbf2, drbf1), (drbf1, drbf2))):
                if None in pair or (pair[1].id - pair[0].id) < 2:
                    continue

                sql_tuple = (
                    'DELETE FROM FILES WHERE ID > ? AND ID < ?',
                    (pair[0].id, pair[1].id)
                )
                logger.debug(f'self._tgbox_db.FILES.execute(sql_tuple={sql_tuple})')
                await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)

            if drbf2: # Not a last cycle
                previous_drbf2 = drbf2
            else:
                # On last cycle we remove all files from Local
                # which ID is > than the last file in Remote
                sql_tuple = ('DELETE FROM FILES WHERE ID > ?', (drbf1.id,))
                logger.debug(f'self._tgbox_db.FILES.execute(sql_tuple={sql_tuple})')

                await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)
                break

        # Awaiting remainder of import_file coros
        if drbf_to_import:
            await import_stack(drbf_to_import)

        # After all files was imported we will update
        # them with Updated Metadata (if any)
        if dlbf_to_update:
            await gather(*dlbf_to_update)

    async def sync(
            self, drb: 'tgbox.api.remote.DecryptedRemoteBox',
            deep: Optional[bool] = False,
            start_from: Optional[int] = 0,
            timeout: Optional[int] = 15,
            deep_progress_callback: Optional[Callable[[int, int], None]] = None,
            fast_progress_callback: Optional[Callable[[int, str], None]] = None):
        """
        This method will synchronize your LocalBox
        with RemoteBox. All files that not in RemoteBox
        but in Local will be **removed**, all that
        in Remote but not in LocalBox will be imported.

        drb (``DecryptedRemoteBox``):
            *RemoteBox* associated with this LocalBox.

        deep (``bool``, optional):
            Flag to enable a "deep syncing".

        start_from (``int``, optional):
            Will check files that > start_from [ID].
            Will be used only on deep syncing.

        timeout (``int``, optional):
            How many seconds generator will sleep at every 1000 file.
            By default it's 15 seconds. Don't use too low timeouts or
            you will receive FloodWaitError. Will be used only on Deep
            Sync, Fast Sync will ignore this argument.

        deep_progress_callback (``Callable[[int, int], None]``, optional):
            A callback function accepting two
            parameters: (current_id, last_id).
            Will be used only on deep syncing.

        fast_progress_callback (``Callable[[int, str], None]``, optional):
            A callback function accepting two
            parameters: (file_id, action<str>).
            Will be used only on fast syncing.

            Don't treat this as progressbar. The code
            will call/await the specified callback
            with one of the arguments from below:

            * ``fast_progress_callback(22, 'deleted')`` OR
            * ``fast_progress_callback(22, 'imported')`` OR
            * ``fast_progress_callback(22, 'metadata updated')``

        .. note::
            * By default this method will use a fast
              syncing, from the "Recent Actions" admin
              log. This is the best for changes made
              within 48 hours & useless after. Deep
              syncing will iterate over each file in
              the remote and compare it to local, thus,
              may take a very long time to complete.

            * In fast syncing we will fetch updates to
              Box only from other admins.
        """
        if self.box_channel_id != drb.box_channel_id:
            raise RemoteBoxInaccessible(
                '''LocalBox ID != RemoteBox ID (is different). You should '''
                '''sync LocalBox only from the associated RemoteBox.''')
        if deep:
            await self._deep_sync(drb, start_from, deep_progress_callback, timeout)
        else:
            await self._fast_sync(drb, fast_progress_callback)

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
        except (UnicodeDecodeError, ValueError):
            raise IncorrectKey(
                'BaseKey doesn\'t match with BaseKey of LocalBox') from None
        else:
            self._session = tc.session.save()

            session = AES(basekey).encrypt(self._session.encode())
            self._elb._session = session

            # Also Update API_ID & API_HASH values (In case User
            # changed them in the new TelegramClient instance)

            # API_ID & API_HASH is encrypted with MainKey
            mainkey = make_mainkey(basekey, self._box_salt)

            api_id = AES(mainkey).encrypt(int_to_bytes(tc._api_id))
            api_hash = AES(mainkey).encrypt(bytes.fromhex(tc._api_hash))

            sql_tuple = (
                'UPDATE BOX_DATA SET SESSION=?, API_ID=?, API_HASH=?',
                (session, api_id, api_hash)
            )
            await self._tgbox_db.BOX_DATA.execute(sql_tuple)

    async def search_file(
            self, sf: SearchFilter,
            cache_preview: bool=True,
            reverse: bool=False,
            fetch_count: int=100,
            erase_encrypted_metadata: bool=True) -> AsyncGenerator[
                'DecryptedLocalBoxFile', None]:
        """
        Use this method search for files in your ``DecryptedLocalBox``.

        Arguments:
            sf (``SearchFilter``):
                ``SearchFilter`` with kwargs you like.

            cache_preview (``bool``, optional):
                Will cache preview in file object if ``True``.

            reverse (``bool``, optional):
                If set to ``True``, the local files will be searched in reverse
                order (from newest to oldest, instead of the default oldest
                to newest).

            fetch_count (``int``, optional):
                Amount of files generator will fetch and cache from
                SQLite table before return. ``100`` by default.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedLocalBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        assert fetch_count > 0, 'fetch_count must be > 0'

        sgen = search_generator(
            sf=sf, lb=self, reverse=reverse,
            cache_preview=cache_preview,
            fetch_count=fetch_count,
            erase_encrypted_metadata=erase_encrypted_metadata
        )
        async for file in sgen:
            yield file

    async def prepare_file(
            self, file: Union[BinaryIO, bytes, TelegramVirtualFile],
            file_size: Optional[int] = None,
            file_path: Optional[str, Path] = None,
            cattrs: Optional[Dict[str, Union[bytes]]] = None,
            make_preview: bool=True,
            skip_fingerprint_check: bool=False) -> 'PreparedFile':
        """
        Prepares your file for ``RemoteBox.push_file``

        Arguments:
            file (``BinaryIO``, ``bytes``, ``TelegramVirtualFile``):
                ``file`` data to add to the LocalBox. In most
                cases it's just opened file. If you want to upload
                something else, then you need to implement class
                that have ``read`` & ``name`` methods.

                The method needs to know size of the ``file``, so
                it will try to ask system what size of file on path
                ``file.name``. If it's impossible, method will try to
                seek file to EOF, if file isn't seekable, then we try to
                get size by ``len()`` (as ``__len__`` dunder). If all fails,
                method tries to get ``file.read())`` (with load to RAM).

                Abs file path length must be <= ``self.defaults.FILE_PATH_MAX``;
                If file has no ``name`` and ``file_path`` is not
                specified then it will be ``NO_FOLDER/{prbg(6).hex()}``.

            file_size (``int``, optional):
                Bytelength of ``file``. You can specify
                it if you already know file size.

            file_path (``str``, ``Path``, optional):
                File path of *Box* file (file name must be
                included). If not specified, will be used path
                from the ``BinaryIO``, (``file`` arg) if file
                is not a ``BinaryIO`` then will be used a
                ``self.defaults.DEF_NO_FOLDER``.

                Must be <= ``self.defaults.FILE_PATH_MAX``.

            cattrs (``Dict[str, Union[bytes, None]]``, optional):
                The file's custom metadata attributes that
                will be added to the main metadata. Specified
                dict will be packed with the PackedAttributes.

                Please note that after some operations we
                will create a file metadata. Its limit
                defined as ``self.defaults.METADATA_MAX``. You
                shouldn't overflow this number plus size of
                default metadata; other is up to you.

            make_preview (``bool``, optional):
                Will try to add file preview to
                the metadata if ``True`` (default).

            skip_fingerprint_check (``bool``, optional):
                If ``True``, will skip the File Fingerprint
                check. Change it only if you want to update
                some already uploaded file.
        """
        if isinstance(file, TelegramVirtualFile):
            logger.info('Trying to make a PreparedFile from Telegram file...')

        if file_path is None:
            if hasattr(file,'name') and file.name:
                file_path = Path(file.name).absolute().resolve()
            else:
                file_path = Path(self._defaults.DEF_NO_FOLDER, prbg(8).hex())
        else:
            if isinstance(file_path, str):
                file_path = Path(file_path)

            if len(file_path.parts) < 2:
                raise ValueError('Path should contain folder and file name')

        if len(str(file_path).encode()) > self._defaults.FILE_PATH_MAX:
            raise LimitExceeded(f'File path must be <= {self._defaults.FILE_PATH_MAX} bytes.')

        file_fingerprint = make_file_fingerprint(self._mainkey, file_path)
        logger.debug(f'File fingerprint is {file_fingerprint.hex()}')

        if not skip_fingerprint_check:
            await self._check_fingerprint(file_fingerprint)

        if not file_size:
            if isinstance(file, TelegramVirtualFile):
                file_size = file.size
            else:
                logger.debug('file_size is not specified')
                try:
                    logger.debug('Trying to guess with getsize...')
                    file_size = getsize(file.name)
                except (FileNotFoundError, AttributeError):
                    if isinstance(file, bytes):
                        logger.debug('"file" is bytes, will get file_size with len.')
                        file_size = len(file)
                        file = BytesIO(file)

                    elif hasattr(file, '__len__'):
                        logger.debug('"file" has __len__ dunder, use as file_size.')
                        file_size = len(file)

                    elif hasattr(file,'seek') and file.seekable():
                        logger.debug(
                            '''"file" has a seek() method, we will use '''
                            '''it to obtain file_size.'''
                        )
                        file.seek(0,2)
                        file_size = file.tell()
                        file.seek(0,0)
                    else:
                        logger.warning(
                            '''You didn\'t specified a file_size, so the best '''
                            '''option for now is read a whole file to RAM and '''
                            '''get a length of it. Change your code to omit this.'''
                        )
                        rb = file.read()
                        file_size = len(rb)
                        file = BytesIO(rb)
                        del rb

        if isinstance(file, TelegramVirtualFile):
            if file.mime:
                mime_type = file.mime
                file_type = mime_type.split('/')[0]
            else:
                mime_type = ''
                file_type = None
        else:
            try:
                mime_type = filetype_guess(file).mime
                file_type = mime_type.split('/')[0]
            except (TypeError, FileNotFoundError, AttributeError):
                mime_type = ''
                file_type = None
            finally:
                # filetype.guess reads N bytes and
                # doesn't seek back.
                file.seek(0,0)

        preview, duration = b'', 0

        if isinstance(file, TelegramVirtualFile):
            if make_preview:
                preview = await file.get_preview()

            duration = file.duration

        elif make_preview and file_type in ('audio','video','image'):
            try:
                logger.debug(f'Trying to make_media_preview({file.name})...')
                preview = (await make_media_preview(file.name)).read()
            except PreviewImpossible:
                logger.debug(f'Failed! Probably because {file.name} is not a media.')

            if file_type in ('audio','video'):
                try:
                    logger.debug(f'Trying to get_media_duration({file.name})...')
                    duration = await get_media_duration(file.name)
                except DurationImpossible:
                    logger.debug(f'Failed! Probably because {file.name} is not a media.')

        # --- Start constructing metadata here --- #

        logger.debug(f'Constructing metadata for {file_path.name}')

        file_salt, file_iv = FileSalt.generate(), IV.generate()

        for path_part in ppart_id_generator(file_path.parent, self._mainkey):
            ppath_head = path_part[2]

        # DirectoryKey is the Key used to make a FileKey started
        # from the v1.3. Instead of making FileKey with the
        # MainKey, we can create a DirectoryKey, which will
        # be identical for each file with the same file_path.
        # This will give us ability to share the whole
        # directory with the some user, we will just need
        # to share DirectoryKey. DirectoryKey doesn't
        # encrypt anything, we use it only to make keys
        dirkey = make_dirkey(self._mainkey, ppath_head)
        # FileKey is a Key that encrypts File and it's
        # metadata (except the efile_path [- MainKey]).
        filekey = make_filekey(dirkey, file_salt)
        # HMACKey is a Key that will be used to make
        # a HMAC of File on upload. It's a result of
        # HMAC(filekey, file_salt)
        hmackey = make_hmackey(filekey, file_salt)

        # We should always encrypt FILE_PATH with MainKey.
        file_path_no_name = str(file_path.parent).encode()
        efile_path = AES(self._mainkey).encrypt(file_path_no_name)

        cattrs = PackedAttributes.pack(**cattrs) if cattrs else b''
        minor_version = int_to_bytes(MINOR_VERSION)

        secret_metadata = PackedAttributes.pack(
            preview = preview,
            duration = int_to_bytes(duration),
            file_size = int_to_bytes(file_size),
            file_name = file_path.name.encode(),
            mime = mime_type.encode(),
            cattrs = cattrs,
            has_hmac_sha256 = b'\x01', # To signal that File has HMAC

            # The 'has_hmac_sha256' will be protected to NOT
            # be in the Start OR End of packed string. This
            # will ensure that if Secret Metadata will be
            # Bit-Flipped, then the whole PackedAttributes
            # will be invalid & unpack with errors.
            protected_keys = ('has_hmac_sha256',)
        )
        # v1.5: Here comes the Protection against the Bit-Flipping
        # attack. In TGBOX, it was small and insignificant breach.
        # You can read more about this Protection in the Docs.
        #  -
        # (1) Started from the v1.5, PackedAttributes will always shuffle
        # all key/value positions. This will prevent attacker from
        # understanding the structure of Secret Metadata. As we *must*
        # support files without HMAC from previous versions, we will
        # check if 'secret_metadata' has 'has_hmac_sha256' key. See Docs.
        #  ---
        # (2.0) Started from the v1.5, first argument of Secret Metadata
        # will be *always* the '_BFP' (protection) with Pseudo Random
        # 5 len bytestring. This will prevent attacker from Bit-Fliping
        # first CBC block by changing IV (which doesn't create any
        # garbage in the text after Decryption), as '_BFP' doesn't
        # really do anything and will be ignored on unpack.
        #  ---
        # (2.1)
        # Any garbage in the unpacked 'secret_metadata' on file
        # decryption process will result in Error due to way the
        # PackedAttributes algorithm works. This way, we don't
        # need to add HMAC to 'secret_metadata' and break the
        # backward-compatibility with versions < 1.5.
        protection = PackedAttributes.pack(_BFP=prbg(5))
        secret_metadata = protection + secret_metadata[1:]

        secret_metadata = AES(filekey).encrypt(secret_metadata)

        metadata = PackedAttributes.pack(
            box_salt = self._box_salt.salt,
            file_salt = file_salt.salt,
            file_fingerprint = file_fingerprint,
            minor_version = minor_version,
            efile_path = efile_path,
            secret_metadata = secret_metadata
        )
        if len(metadata) > self._defaults.METADATA_MAX:
            raise LimitExceeded(
                f'Total len(metadata) must be <= {self._defaults.METADATA_MAX}'
            )
        if len(metadata) > 256**3-1:
            raise LimitExceeded(
                'Total len(metadata) must be <= 256^3-1'
            )
        metadata_bytesize = int_to_bytes(len(metadata),3)

        constructed_metadata =  PREFIX + VERBYTE
        constructed_metadata += metadata_bytesize
        constructed_metadata += metadata + file_iv.iv

        total_file_size = len(constructed_metadata) + file_size
        # We don't know if user has Premium or not, because
        # we can't access TelegramClient from 'prepare_file',
        # so here we check only against the maximum allowed
        # size, and in 'push_file' we will check for actual
        if total_file_size > UploadLimits.PREMIUM:
            raise LimitExceeded(
                f'''Max allowed filesize in Telegram is {UploadLimits.PREMIUM} '''
                f'''bytes, your file is {total_file_size} bytes in size.'''
            )
        return PreparedFile(
            dlb = self,
            file = file,
            filekey = filekey,
            filesize = total_file_size,
            filepath = Path(file_path_no_name.decode()),
            filesalt = file_salt,
            hmackey = hmackey,
            fingerprint = file_fingerprint,
            metadata = constructed_metadata,
            imported = False
        )
    async def import_file(
            self, drbf: 'tgbox.api.remote.DecryptedRemoteBoxFile',
            file_path: Optional[Union[str, Path]] = None)\
            -> 'DecryptedLocalBoxFile':
        """
        Imports file to your ``DecryptedLocalBox``

        Arguments:
            drbf (``DecryptedRemoteBoxFile``):
                Remote file you want to import.

            file_path (``Path``, optional):
                File's path. Will be used ``drbf._file_path`` if
                ``None`` and if drbf was decrypted with the
                ``MainKey``, otherwise ``self.defaults.DEF_NO_FOLDER``.

                This method will call a ``set_file_path(file_path)``
                on the specified drbf if ``file_path`` isn't a ``None``.

                You can change drbf ``file_path`` with
                ``set_file_path`` method before importing
                file, so you don't need to specify it here.
        """
        # We need to fetch encrypted metadata
        if not drbf._erbf._initialized:
            logger.debug(f'Fetching encrypted metadata of ID{drbf.id}')
            await drbf._erbf.init()

        if not file_path:
            update_metadata = False

            if drbf.file_path:
                file_path = drbf.file_path
            else:
                logger.debug(f'ID{drbf.id} doesn\'t have file_path. Set DEF_NO_FOLDER.')
                file_path = self._defaults.DEF_NO_FOLDER
        else:
            update_metadata = True

        if isinstance(file_path, str):
            file_path = Path(file_path)

        drbf.set_file_path(file_path)

        pf = PreparedFile(
            dlb = self,
            file = BytesIO(),
            filekey = drbf._filekey,
            filesize = drbf._size,
            filepath = file_path,
            filesalt = drbf._file_salt,
            hmackey = None, # We don't need HMACKey on importing
            fingerprint = drbf._fingerprint,
            metadata = drbf._erbf._metadata,
            imported = True
        )
        pf.set_file_id(drbf._id)
        pf.set_upload_time(drbf._upload_time)

        dlbf = await self._make_local_file(pf)

        if update_metadata:
            await dlbf.update_metadata(dlb=self,
                changes={'file_path': str(file_path).encode()}
            )
        return dlbf

    async def get_directory(self, path: Union[Path, str])\
            -> Union[DecryptedLocalBoxDirectory, None]:
        """
        This method will make ``DecryptedLocalBoxDirectory``
        from your ``path``. If such path is not presented in
        LocalBox, then ``None`` will be returned.

        Arguments:
            path (``Path``, ``str``):
                Absolute path from which you want to
                make an ``DecryptedLocalBoxDirectory``.
        """
        ppidg = ppart_id_generator(
            path = make_general_path(path),
            mainkey = self._mainkey
        )
        part_id = None
        for part in ppidg:
            part_id = part[2]
        try:
            return await EncryptedLocalBoxDirectory(
                self._elb, part_id).decrypt(dlb=self)
        except StopAsyncIteration:
            # StopAsyncIteration will be raised on parsing the SELECT
            # results if specified dir is not presented in LocalBox
            return None

    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this Box. You should use
        this method if you want to share your LocalBox
        with other people.

        Arguments:
            reqkey (``RequestKey``, optional):
                Requester's ``RequestKey``. If isn't specified
                returns ``ImportKey`` of this box without
                encryption, so anyone with this key can
                decrypt **ALL** files in your Boxes.
        """
        if reqkey:
            return make_sharekey(self._mainkey, self._box_salt, reqkey)

        return make_sharekey(self._mainkey)

class EncryptedLocalBoxDirectory:
    """
    Class that represents abstract tgbox directory. You
    can iterate over all files/folders in it, as well
    as load parent folder up to root.

    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_localbox
        from tgbox.keys import make_basekey, Phrase

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_localbox(basekey)
            dlbfi = await dlb.get_file(await dlb.get_last_file_id())

            # Load directory up to the root
            await dlbfi.directory.lload(full=True)

            print(dlbfi.directory)

            # Iterate over files/folders in this directory
            async for content in dlbfi.directory.iterdir():
                print(content) # May be file or another dir

        asyncio_run(main())
    """
    def __init__(self, elb: EncryptedLocalBox, part_id: bytes):
        """
        Arguments:
            elb (``EncryptedLocalBox``):
                Encrypted LocalBox.

            part_id (``bytes``):
                Path's part ID. You can fetch it from
                the ``PATH_PARTS`` table in ``TgboxDB``.
        """
        self._is_encrypted = True
        self._initialized = False

        self._lb = elb
        self._tgbox_db = self._lb._tgbox_db

        self._part = None
        self._part_id = part_id
        self._parent_part_id = None

        self._parts = [self]
        self._floaded = False

    def __hash__(self) -> int:
        x = tuple(i.part for i in self._parts)
        # Without 22 hash of tuple will be equal to object's
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
        c = 'ELBD' if self._is_encrypted else 'DLBD'
        return f'{c}[{self.part.decode() if c == "DLBD" else self.part}]'

    def __getitem__(self, _slice: slice):
        return self.parts[_slice]

    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().')

    @property
    def is_encrypted(self) -> bool:
        """
        Will return ``True`` if this is an *Encrypted*
        class, ``False`` if *Decrypted*
        """
        return self._is_encrypted

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

    @property
    def tgbox_db(self) -> TgboxDB:
        """Will return TgboxDB associated with this directory"""
        return self._tgbox_db

    async def init(self) -> 'EncryptedLocalBoxDirectory':
        """Will fetch required data from the database."""

        logger.debug(
            '''Init ELBD |  SELECT * FROM PATH_PARTS '''
           f'''WHERE PART_ID={self._part_id}'''
        )
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

        while True:
            logger.debug(
                '''Loading the parent path part | SELECT PARENT_PART_ID '''
               f'''FROM PATH_PARTS WHERE PART_ID={self.parts[0].part_id}'''
            )
            previous_part = await self._tgbox_db.PATH_PARTS.select_once((
                'SELECT PARENT_PART_ID FROM PATH_PARTS WHERE PART_ID=?',
                (self.parts[0].part_id,)
            ))
            if not previous_part[0]:
                self._floaded = True
                return

            if isinstance(self._lb, DecryptedLocalBox):
                elbd = EncryptedLocalBoxDirectory(self._lb._elb, previous_part[0])
                previous_part = await elbd.decrypt(dlb=self._lb)
            else:
                previous_part = await EncryptedLocalBoxDirectory(
                    self._lb, previous_part[0]).init()

            self.parts.insert(0, previous_part)

            if not full: break

        return previous_part

    async def iterdir(
        self,
        ignore_dirs: bool=False,
        ignore_files: bool=False,
        cache_preview: bool=True,
        ppid: Optional[Union[bytes, DirectoryRoot]] = None,
        erase_encrypted_metadata: Optional[bool] = True) -> Union[
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

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedLocalBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
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
            while True:
                logger.debug('Trying to fetch new portion of local dirs (100)...')
                pending = await folders.fetchmany(100)
                if not pending: break # No more files

                to_gather = []
                for folder_row in pending:
                    if isinstance(self._lb, DecryptedLocalBox):
                        elbd = EncryptedLocalBoxDirectory(self._lb._elb, folder_row[1])
                        to_gather.append(elbd.decrypt(dlb=self._lb))
                    else:
                        to_gather.append(
                            EncryptedLocalBoxDirectory(
                                self._lb, folder_row[1]).init()
                        )
                pending = await gather(*to_gather)

                while pending:
                    yield pending.pop(0)

        if not ignore_files:
            files = await self._tgbox_db.FILES.execute((
                'SELECT * FROM FILES WHERE PPATH_HEAD IS ?',
                (part_id,)
            ))
            while True:
                logger.debug('Trying to fetch new portion of local files (100)...')
                pending = await files.fetchmany(100)
                if not pending: break # No more files

                pending = [
                    self._lb.get_file(file_row[0],
                        cache_preview=cache_preview,
                        erase_encrypted_metadata=erase_encrypted_metadata
                    )
                    for file_row in pending
                ]
                pending = await gather(*pending)

                while pending:
                    yield pending.pop(0)

    async def get_files_total(self) -> int:
        """Will return a total number of files in this directory"""
        cursor = await self._tgbox_db.FILES.execute((
            'SELECT count(*) FROM FILES WHERE PPATH_HEAD IS ?',
            (self.part_id,))
        )
        return (await cursor.fetchone())[0]

    async def get_folders_total(self) -> int:
        """Will return a total number of folders in this directory"""
        cursor = await self._tgbox_db.PATH_PARTS.execute((
            'SELECT count(*) FROM PATH_PARTS WHERE PARENT_PART_ID IS ?',
            (self.part_id,))
        )
        return (await cursor.fetchone())[0]

    async def get_contents_total(self) -> int:
        """Will return a total number of contents in this directory"""
        total_files = await self.get_files_total()
        total_folders = await self.get_folders_total()

        return total_files + total_folders

    async def delete(self) -> None:
        """
        Will delete this directory with all sub-dirs and files
        from your LocalBox. All of them will stay in ``RemoteBox``,
        so you can restore all your data by syncing Box.
        """
        logger.debug(f'DELETE FROM FILES WHERE PPATH_HEAD={self._part_id}')
        await self._tgbox_db.FILES.execute(
            ('DELETE FROM FILES WHERE PPATH_HEAD=?',(self._part_id,))
        )
        logger.debug(f'DELETE FROM PATH_PARTS WHERE PART_ID={self._part_id}')
        await self._tgbox_db.PATH_PARTS.execute(
            ('DELETE FROM PATH_PARTS WHERE PART_ID=?',(self._part_id,))
        )
        logger.debug(f'DELETE FROM PATH_PARTS WHERE PARENT_PART_ID={self._part_id}')
        await self._tgbox_db.PATH_PARTS.execute(
            ('DELETE FROM PATH_PARTS WHERE PARENT_PART_ID=?',(self._part_id,))
        )
    async def decrypt(
            self, key: Optional[Union[BaseKey, MainKey]] = None,
            dlb: Optional[DecryptedLocalBox] = None):
        """
        Decrypt self and return ``DecryptedLocalBoxDirectory``

        Arguments:
            key (``BaseKey``, ``MainKey``, optional):
                Decryption key. Must be specified if ``dlb`` is ``None``.

            dlb (``DecryptedLocalBox``, optional):
                ``DecryptedLocalBox`` that we will use to decrypt
                ``EncryptedLocalBoxDirectory``. Must be specified
                if ``key`` argument is ``None``.
        """
        if not any((key, dlb)):
            raise ValueError('At least key or dlb must be specified')

        if not self._initialized:
            await self.init()

        return DecryptedLocalBoxDirectory(self, key=key, dlb=dlb)

class DecryptedLocalBoxDirectory(EncryptedLocalBoxDirectory):
    def __init__(
            self, elbd: EncryptedLocalBoxDirectory,
            key: Optional[Union[BaseKey, MainKey]] = None,
            dlb: Optional[DecryptedLocalBox] = None):
        """
        Arguments:
            elbd (``EncryptedLocalBoxDirectory``):
                Initialized ``EncryptedLocalBoxDirectory``.

            key (``BaseKey``, ``MainKey``):
                Decryption ``Key``. Must be specified if ``dlb`` is ``None``.

            dlb (``DecryptedLocalBox``, optional):
                ``DecryptedLocalBox`` that we will use to decrypt
                ``EncryptedLocalBoxDirectory``. Must be specified
                if ``key`` argument is ``None``.
        """
        if not any((key, dlb)):
            raise ValueError('At least key or dlb must be specified')

        super().__init__(elbd._lb, elbd._part_id)

        self._is_encrypted = False
        self._initialized = True
        self._elbd = elbd

        if dlb:
            self._lb = dlb
        else:
            self._lb = self._elbd._lb.decrypt(key)

        self._part = AES(self._lb._mainkey).decrypt(elbd._part)

    @staticmethod
    async def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxDirectory`` """
            """and cannot be used on ``DecryptedLocalBoxDirectory``."""
        )
    @staticmethod
    async def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxDirectory`` """
            """and cannot be used on ``DecryptedLocalBoxDirectory``."""
        )
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this file. You should
        use this method if you want to share **ALL**
        files from this directory with other user.

        Use the same method on the ``DecryptedLocalBoxFile``
        to share **only one** file with some Requester.

        Arguments:
            reqkey (``RequestKey``, optional):
                Requester's ``RequestKey``. If isn't specified,
                returns ``ShareKey`` of this directory without
                encryption, so ANYONE with this key can decrypt
                files from this Directory in Local & Remote.
        """
        dirkey = make_dirkey(self._lb._mainkey, self._part_id)

        if reqkey:
            return make_sharekey(dirkey, self._part_id, reqkey)

        return make_sharekey(dirkey)

class EncryptedLocalBoxFile:
    """
    This class represents an encrypted local file. On
    more low-level that's a wrapper around row of
    ``FILES`` table in Tgbox Database. Usually you
    will not use this in your code.

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_localbox
        from tgbox.keys import make_basekey, Phrase

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_localbox(basekey)

            elbf = await dlb.get_file(
                id = await dlb.get_last_file_id(),
                decrypt = False
            )
            print(elbf.file_salt.hex())
            print(elbf.box_salt.hex())

        asyncio_run(main())
    """
    def __init__(
            self, id: int, elb: EncryptedLocalBox,
            cache_preview: bool=True) -> None:
        """
        Arguments:
            id (``int``):
                File ID.

            elb (``EncryptedLocalBox``):
                Encrypted LocalBox.

            cache_preview (``bool``, optional):
                Cache preview in class or not.
        """
        self._id = id
        self._lb = elb
        self._cache_preview = cache_preview

        self._defaults = self._lb._defaults

        self._is_encrypted = True
        self._initialized = False

        self._fingerprint = None
        self._updated_metadata = None

        self._directory, self._prefix = None, None
        self._ppath_head, self._upload_time = None, None
        self._imported, self._efilekey = None, None
        self._file_salt, self._version_byte = None, None
        self._file_iv, self._box_salt = None, None
        self._secret_metadata, self._minor_version = None, None
        self._efile_path = None

    def __repr__(self) -> str:
        return (f'{self.__class__.__name__}({self._id}, {repr(self._lb)}, {self._cache_preview})')

    def __str__(self) -> str:
        file_salt = None if not self._initialized else urlsafe_b64encode(self._file_salt.salt).decode()
        return (
            f'''{self.__class__.__name__}({self._id}, {repr(self._lb)}, {self._cache_preview}) # '''
            f'''{self._initialized=}, {file_salt=}'''
        )
    def __hash__(self) -> int:
        return hash((self._id, 22))

    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__),
            self.__hash__() == hash(other)
        ))
    @property
    def is_encrypted(self) -> bool:
        """
        Will return ``True`` if this is an *Encrypted*
        class, ``False`` if *Decrypted*
        """
        return self._is_encrypted

    @property
    def initialized(self) -> bool:
        """
        Returns ``True`` if you
        already called ``.init()``
        """
        return self._initialized

    @property
    def imported(self) -> Union[bool, None]:
        """
        Returns ``True`` if file was
        forwarded to your BoxChannel.
        """
        return self._imported

    @property
    def fingerprint(self) -> Union[bytes, None]:
        """
        Returns file fingerprint (hash of
        file path plus mainkey) or ``None``
        """
        return self._fingerprint

    @property
    def version_byte(self) -> Union[bytes, None]:
        """Returns Verbyte of this file or
        ``None`` if class wasn't initialized
        """
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
    def defaults(self) -> Union[DefaultsTableWrapper, RemoteBoxDefaults]:
        """
        Will return ``DefaultsTableWrapper`` or
        ``RemoteBoxDefaults``.
        """
        return self._defaults

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

    @property
    def file_iv(self) -> Union[bytes, None]:
        """
        Returns file IV or ``None``
        if file wasn't initialized
        """
        return self._file_iv

    @property
    def file_salt(self) -> Union[FileSalt, None]:
        """
        Returns file salt or ``None``
        if file wasn't initialized
        """
        return self._file_salt

    @property
    def box_salt(self) -> Union[BoxSalt, None]:
        """
        Returns box salt or ``None``
        if file wasn't initialized
        """
        return self._box_salt

    @property
    def prefix(self) -> Union[bytes, None]:
        """
        Returns file prefix or ``None``
        if file wasn't initialized
        """
        return self._prefix

    @property
    def lb(self) -> Union[EncryptedLocalBox, DecryptedLocalBox]:
        """
        Will return ``EncryptedLocalBox`` from the
        ``EncryptedLocalBoxFile`` and ``DecryptedLocalBox``
        from the ``DecryptedLocalBoxFile`` object.
        """
        return self._lb

    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().')

    async def init(self) -> 'EncryptedLocalBoxFile':
        """Will fetch and parse data from the Database."""

        logger.debug(f'Init ELBF | SELECT * FROM FILES WHERE ID={self._id}')

        file_row = list(await self._lb._tgbox_db.FILES.select_once(
            sql_tuple = ('SELECT * FROM FILES WHERE ID=?', (self._id,))
        ))
        self._updated_metadata = file_row.pop()
        metadata = file_row.pop()
        self._fingerprint = file_row.pop()
        self._efilekey = file_row.pop()
        self._ppath_head = file_row.pop()
        self._upload_time = file_row.pop()
        self._id = file_row.pop()

        self._directory = EncryptedLocalBoxDirectory(
            self._lb, self._ppath_head
        )
        await self._directory.init()

        self._imported = bool(self._efilekey)

        self._prefix = metadata[:len(PREFIX)]
        self._version_byte = metadata[
            len(PREFIX) : len(VERBYTE) + len(PREFIX)
        ]
        pattr_offset = len(PREFIX) + len(VERBYTE) + 3

        unpacked_metadata = PackedAttributes.unpack(
            metadata[pattr_offset:-16]
        )
        self._file_iv = metadata[-16:]

        self._file_salt = FileSalt(unpacked_metadata['file_salt'])
        self._box_salt = BoxSalt(unpacked_metadata['box_salt'])
        self._secret_metadata = unpacked_metadata['secret_metadata']
        # Metadata include the efile_path field started from the
        # version 1.3. Previously it was in the Secret Metadata,
        # now it's a part of Public Metadata so we can easily
        # decrypt it with MainKey and make a DirectoryKey
        self._efile_path = unpacked_metadata.get('efile_path', None)
        # Metadata include the minor_version field started from
        # the version 1.3. We use it to enable a more
        # straightforward backward compatibility
        self._minor_version = unpacked_metadata.get('minor_version', -1)

        if isinstance(self._minor_version, bytes):
            self._minor_version = bytes_to_int(self._minor_version)

        if isinstance(self._defaults, DefaultsTableWrapper):
            if not self._defaults.initialized:
                await self._defaults.init()

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

    async def decrypt(
            self, key: Optional[Union[FileKey, MainKey, ImportKey]] = None,
            dlb: Optional[DecryptedLocalBox] = None,
            erase_encrypted_metadata: bool=True) -> 'DecryptedLocalBoxFile':
        """
        Returns decrypted by ``key``/``dlb`` ``EncryptedLocalBoxFile``

        Arguments:
            key (``FileKey``, ``MainKey``, ``ImportKey``):
                Decryption key. Must be specified if
                ``dlb`` argument is ``None``.

            dlb (``DecryptedLocalBox``, optional):
                Decrypted LocalBox. Must be specified
                if ``key`` argument is ``None``.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata from the parent
                ``EncryptedLocalBoxFile`` after decryption
                to save more RAM if ``True``. You can call
                ``.init()`` method on it to load it again.
        """
        if not any((key, dlb)):
            raise ValueError('You should specify at least key or dlb')

        if not self.initialized:
            await self.init()

        return DecryptedLocalBoxFile(self, key=key, dlb=dlb,
            erase_encrypted_metadata=erase_encrypted_metadata)

    async def delete(self, remove_empty_directories: Optional[bool] = False) -> None:
        """
        Will delete this file from your LocalBox. You can
        re-import it from ``RemoteBox`` with ``import_file``.

        remove_empty_directories (``bool``, optional):
            If ``True``, will remove orphaned directories
            that left after removing files (if any).

            Alternative: ``dlb.remove_empty_directories()``

        .. note::
            This will delete file only from your LocalBox.
            To completly remove your file use same
            function on ``EncryptedRemoteBoxFile``.
        """
        await self._lb.delete_files(self,
            remove_empty_directories=remove_empty_directories)

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
        return make_requestkey(mainkey, self._file_salt)

class DecryptedLocalBoxFile(EncryptedLocalBoxFile):
    """
    This class represents an decrypted local file.
    On more low-level that's a wrapper of ``FILES``
    table in Tgbox Database that decrypts row.

    Typical usage:

    .. code-block:: python

        from asyncio import run as asyncio_run
        from tgbox.api import get_localbox
        from tgbox.keys import make_basekey, Phrase

        phrase = Phrase(b'example phrase here')
        basekey = make_basekey(phrase)

        async def main():
            dlb = await get_localbox(basekey)
            lfid = dlb.get_last_file_id()
            dlbfi = await dlb.get_file(lfid)

            print(dlbfi.id, dlbfi.id, dlbfi.size)

        asyncio_run(main())
    """
    def __init__(
            self, elbf: EncryptedLocalBoxFile,
            key: Optional[Union[FileKey, ImportKey, MainKey]] = None,
            dlb: Optional[DecryptedLocalBox] = None,
            cache_preview: Optional[bool] = None,
            erase_encrypted_metadata: bool=True):
        """
        Arguments:
            elbf (``EncryptedLocalBoxFile``):
                Encrypted local box file that
                you want to decrypt.

            key (``FileKey``, ``ImportKey``, ``MainKey``, optional):
                Decryption key. If ``key`` is ``MainKey``,
                ``EncryptedLocalBox`` attached to the ``elbf``
                will be auto-decrypted too (self.lb). Must be
                specified if ``dlb`` is ``None``.

            dlb (``DecryptedLocalBox``, optional):
                Decrypted LocalBox associated with the
                EncryptedLocalBoxFile you want to decrypt.
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
        if not any((key, dlb)):
            raise ValueError('At least key or dlb must be specified')

        if not elbf._initialized:
            raise NotInitializedError('EncryptedLocalBoxFile must be initialized.')

        self._is_encrypted = False
        self._initialized = True

        self._elbf = elbf
        self._key = key

        if dlb:
            self._lb = dlb
        else:
            self._lb = elbf._lb

        self._efilekey = elbf._efilekey

        self._id = elbf._id
        self._imported = elbf._imported
        self._ppath_head = elbf._ppath_head

        self._fingerprint = elbf._fingerprint
        self._updated_metadata = elbf._updated_metadata
        self._defaults = elbf._defaults

        self._prefix = elbf._prefix
        self._version_byte = elbf._version_byte
        self._file_iv = elbf._file_iv
        self._file_salt = elbf._file_salt
        self._box_salt = elbf._box_salt
        self._minor_version = elbf._minor_version

        self._file_path = None

        if cache_preview is None:
            self._cache_preview = elbf._cache_preview
        else:
            self._cache_preview = cache_preview

        self._erase_encrypted_metadata = erase_encrypted_metadata


        if isinstance(key, MainKey):
            logger.debug('key is MainKey, self._mainkey is present')
            self._mainkey = key

            logger.debug('Decrypting EncryptedLocalBox with MainKey')
            self._lb = DecryptedLocalBox(self._lb, self._mainkey)

        elif isinstance(self._lb, DecryptedLocalBox):
            self._mainkey = self._lb._mainkey
        else:
            self._mainkey = None


        # Prior to v1.3, the EFILE_PATH was a part of the Secret Metadata,
        # thus, was *always* None before decryption. Started from the v1.3,
        # the EFILE_PATH is now in a Public Metadata, so we can easily
        # decrypt it with MainKey, then make a DirectoryKey, and then
        # make a FileKey, which will decrypt File and Secret Metadata.
        # This "If Statement" will be True only if File is version 1.3+
        if self._mainkey and elbf._efile_path is not None and not self._imported:
            self._file_path = AES(self._mainkey).decrypt(elbf._efile_path)
            self._file_path = make_general_path(self._file_path.decode())

            self._original_file_path = self._file_path

            for path_part in ppart_id_generator(self._file_path, self._mainkey):
                ppath_head = path_part[2]

            self._dirkey = make_dirkey(self._mainkey, ppath_head)
        else:
            if elbf._efile_path: # v1.3+ but no MainKey
                logger.warning(
                   f'''We can\'t decrypt real file path of ID{self._id} because '''
                    '''MainKey is not presented. Try to decrypt EncryptedRemoteBoxFile '''
                    '''with MainKey to fix this. Setting to DEF_NO_FOLDER...'''
                )
                self._file_path = self._defaults.DEF_NO_FOLDER

            self._dirkey = None


        if isinstance(key, FileKey):
            logger.debug('Treating key as FileKey')
            self._filekey = FileKey(key.key)

        elif isinstance(key, ImportKey):
            try:
                logger.debug('Trying to treat key as DirectoryKey...')

                filekey = make_filekey(key, self._file_salt)
                assert len(AES(filekey).decrypt(elbf._upload_time)) < 16
                # ^ ImportKey can be DirectoryKey, so here we're try
                #   to treat it as dirkey and make FileKey from it,
                #   then, we try to decrypt some Metadata field to
                #   check if decryption will fail or not. If not, --
                #   it's definitely a DirectoryKey.
                #
                # | Decryption can fail with ValueError (invalid
                #   padding bytes OR by `assert` statement. The
                #   upload_time after decryption should be less
                #   than 16 bytes in size (decryption failed)
                self._filekey = filekey
                self._dirkey = DirectoryKey(key)
            except (ValueError, AssertionError):
                logger.debug('ImportKey is not DirectoryKey, so treating as FileKey')
                self._filekey = FileKey(key.key)

        elif self._mainkey and self._efilekey:
            logger.debug('Trying to decrypt encrypted FileKey with MainKey')
            self._filekey = FileKey(AES(self._mainkey).decrypt(self._efilekey))

        elif self._mainkey and not self._efilekey:
            if self._dirkey:
                logger.debug('Making FileKey from the DirectoryKey and FileSalt (>= v1.3)')
                self._filekey = make_filekey(self._dirkey, self._file_salt)
            else:
                logger.debug('Making FileKey from the MainKey and FileSalt (< v1.3)')
                self._filekey = make_filekey(self._mainkey, self._file_salt)

        else:
            raise ValueError('You need to specify FileKey | MainKey | DecryptedLocalBox')

        try:
            self._upload_time = AES(self._filekey).decrypt(elbf._upload_time)
        except ValueError:
            raise AESError('Can\'t decrypt Metadata attr. Incorrect key?') from None

        self._upload_time = bytes_to_int(self._upload_time)

        logger.debug(f'Decrypting & unpacking secret metadata of ID{self._id}...')

        secret_metadata = AES(self._filekey).decrypt(
            self._elbf._secret_metadata
        )
        secret_metadata = PackedAttributes.unpack(secret_metadata)

        if not secret_metadata: # secret_metadata can't be empty dict
            raise AESError('Metadata wasn\'t decrypted correctly. Incorrect key?')

        self.__required_metadata = [
            'duration', 'file_size', 'file_name',
            'cattrs', 'mime', 'preview'
        ]
        for attr in self.__required_metadata:
            setattr(self, f'_{attr}', secret_metadata[attr])

        self._size = bytes_to_int(self._file_size) # pylint: disable=no-member
        del self._file_size # pylint: disable=no-member

        self._duration = bytes_to_int(self._duration)
        self._cattrs = PackedAttributes.unpack(self._cattrs)
        self._mime = self._mime.decode()

        self._file_name = self._file_name.decode()

        if not self._cache_preview:
            logger.debug('cache_preview is False, DRBF preview won\'t be saved.')
            self._preview = b''

        if self._file_path is None:
            # File was uploaded from Version < 1.3
            if self._mainkey and not self._imported:
                logger.debug('Decrypting efile_path with the MainKey')

                # Prior v1.3, the EFILE_PATH was a part of the Secret Metadata.
                self._file_path = AES(self._mainkey).decrypt(
                    secret_metadata['efile_path'])

                # Started from the v1.3, the EFILE_PATH is not a
                # part of the Required Metadata fields.
                secret_metadata.pop('efile_path')

                self._file_path = Path(self._file_path.decode())
                self._original_file_path = self._file_path
            else:
                logger.warning(
                   f'''We can\'t decrypt real file path of ID{self._id} because '''
                    '''MainKey is not present. Try to decrypt EncryptedLocalBoxFile '''
                    '''with MainKey to fix this. Setting to DEF_NO_FOLDER...'''
                )
                self._file_path = self._defaults.DEF_NO_FOLDER

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

        if self._mainkey:
            self._directory = DecryptedLocalBoxDirectory(
                self._elbf._directory, dlb=self._lb)
        else:
            self._directory = self._elbf._directory

        self._download_path = self._defaults.DOWNLOAD_PATH

        if self._elbf._updated_metadata:
            logger.debug(f'Updates to metadata for ID{self._id} found. Applying...')
            try:
                updates = AES(self._filekey).decrypt(
                    self._elbf._updated_metadata
                )
                updates = PackedAttributes.unpack(updates)
            except Exception as e:
                logger.warning(f'Failed to unpack updated metadata {e}. Ignoring..')
            else:
                for k,v in tuple(updates.items()):
                    if k in (*self.__required_metadata, 'efile_path'):
                        if k == 'cattrs':
                            self._cattrs.update(PackedAttributes.unpack(v))

                        elif k == 'duration':
                            setattr(self, f'_{k}', bytes_to_int(v))

                        elif k == 'efile_path' and self._mainkey:
                            self._file_path = AES(self._mainkey).decrypt(v)
                            self._file_path = Path(self._file_path.decode())
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

        if self._erase_encrypted_metadata:
            self._elbf._initialized = False
            self._elbf._secret_metadata = None
            self._elbf._updated_metadata = None

    @property
    def filekey(self) -> FileKey:
        """Returns ``FileKey`` of this file."""
        return self._filekey

    @property
    def dirkey(self) -> Union[DirectoryKey, None]:
        """Returns ``DirectoryKey`` of this file if present."""
        return self._dirkey

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
    def has_hmac_sha256(self) -> bool:
        """Will return ``True`` if file has HMAC (v1.5+)"""
        return self._has_hmac_sha256

    @property
    def hmackey(self) -> Union[HMACKey, None]:
        """Returns ``HMACKey`` of this file if present."""
        return self._hmackey

    @property
    def file_path(self) -> Path:
        """Returns file path."""
        return self._file_path

    @property
    def file_name(self) -> str:
        """Returns file name."""
        return self._file_name

    @property
    def preview(self) -> Union[bytes, None]:
        """
        Returns preview bytes or ``b''``
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

    @staticmethod
    async def init() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxFile`` """
            """and cannot be used on ``DecryptedLocalBoxFile``."""
        )
    @staticmethod
    async def decrypt() -> NoReturn:
        raise AttributeError(
            """This function was inherited from ``EncryptedLocalBoxFile`` """
            """and cannot be used on ``DecryptedLocalBoxFile``."""
        )

    def set_download_path(self, path: Path):
        """Will set download path to specified."""
        self._download_path = path

    async def refresh_metadata(
            self, drb: Optional['tgbox.api.remote.DecryptedRemoteBox'] = None,
            drbf: Optional['tgbox.api.remote.DecryptedRemoteBoxFile'] = None,
            _updated_metadata: Optional[Union[str, bytes]] = None
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

            drbf (``DecryptedRemoteBoxFile``, optional):
                Remote box file from which we will extract
                metadata. You can use it as alternative to
                the "drb" argument here.

            _updated_metadata (``str``, ``bytes``, optional):
                Updated metadata by itself. This is for
                internal use, specify only ``drb``.

        You should specify at least one argument.
        """
        assert any((drb, drbf, _updated_metadata is not None)), 'Specify at least one'

        if _updated_metadata is not None:
            pass

        elif drbf:
            _updated_metadata = drbf._message.message

        elif drb:
            drbf = await drb.get_file(self._id)
            _updated_metadata = drbf._message.message

        # === Verifying updated metadata for validity === #

        if _updated_metadata:
            if isinstance(_updated_metadata, str):
                _updated_metadata = urlsafe_b64decode(_updated_metadata)
                assert _updated_metadata, 'empty after decode, invalid!'

            updates = AES(self._filekey).decrypt(
                _updated_metadata
            )
            updates = PackedAttributes.unpack(updates)
        else:
            # _updated_metadata can be empty string (''),
            # this means that user requested us to remove
            # all updated metadata from the LocalBox
            _updated_metadata, updates = None, {}

            # We also restore original PPATH_HEAD
            self._file_path = self._original_file_path
            #
            if isinstance(self._lb, DecryptedLocalBox):
                self._directory = await self._lb._make_local_path(self._file_path)

                await self._lb._tgbox_db.FILES.execute((
                    'UPDATE FILES SET PPATH_HEAD=? WHERE ID=?',
                    (self._directory.part_id, self._id)
                ))
            else:
                logger.warning(
                   f'''We can not restore the original PPATH_HEAD of the ID{self._id} '''
                    '''because it wasn\'t decrypted with the DecryptedLocalBox.'''
                )
        # =============================================== #

        logger.debug(
            '''Updating metadata | UPDATE FILES SET '''
           f'''UPDATED_METADATA={_updated_metadata} '''
           f'''WHERE ID={self._id}'''
        )
        await self._lb._tgbox_db.FILES.execute((
            'UPDATE FILES SET UPDATED_METADATA=? WHERE ID=?',
            (_updated_metadata, self._id)
        ))

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
                    if isinstance(self._lb, DecryptedLocalBox) or self._mainkey:
                        mainkey = self._mainkey if self._mainkey else self._lb._mainkey
                        self._file_path = Path(AES(mainkey).decrypt(v).decode())
                    else:
                        logger.warning(
                            '''Updated metadata contains efile_path, however, '''
                            '''DecryptedLocalBoxFile that you trying to update '''
                            '''doesn\'t have a MainKey and wasn\'t decrypted with '''
                            '''the DecryptedLocalBox, so we will ignore new path.''')
                else:
                    # str attributes
                    if k in ('mime', 'file_name'):
                        setattr(self, f'_{k}', v.decode())
                    else:
                        setattr(self, f'_{k}', v)
            else:
                self._residual_metadata[k] = v

    async def update_metadata(
            self, changes: Dict[str, Union[bytes, None]],
            dlb: Optional['DecryptedLocalBox'] = None,
            drb: Optional['DecryptedRemoteBox'] = None,
            drbf: Optional['DecryptedRemoteBoxFile'] = None
        ):
        """This method will "update" file metadata attributes

        In most cases you will want to use the same method on
        the ``DecryptedRemoteBoxFile`` and then refresh
        metadata of the ``DecryptedLocalBoxFile`` via the
        ``refresh_metadata()`` method. This way you will
        update metadata of the Remote **and** Local file.

        However, you may want to update file metadata in
        the **LocalBox only**, and left the RemoteBox
        **untouched**. For such case use this method only.

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
                If current local file wasn't decrypted with the
                DecryptedLocalBox/MainKey then we can't decrypt
                the efile_path (the new file_path) if it's
                present. You can specify a ``DecryptedLocalBox``
                to fix this. You don't need to worry about this
                if you receive files from the ``DecryptedLocalBox``

            drb (``DecryptedRemoteBox``, optional):
                ``DecryptedRemoteBox`` associated with
                this ``DecryptedLocalBox``. Will auto
                refresh your updates in remote. Don't
                specify this if you want to update
                metadata in the LocalBox only.

                If you have ``DecryptedRemoteBoxFile``,
                pass it as ``drbf`` instead.

            drbf (``DecryptedRemoteBoxFile``, optional):
                ``DecryptedRemoteBoxFile`` associated with
                this ``DecryptedLocalBoxFile``. Will auto
                refresh your updates in remote. Don't
                specify this if you want to update
                metadata in the LocalBox only.

        E.g: This code will replace ``file_name`` metadata
        attribute of the ``DecryptedLocalBoxFile``

        .. code-block:: python

                ... # Most code is omited, see help(tgbox.api)
                dlbf = await dlb.get_file(dlb.get_last_file_id())
                await dlbf.update_metadata({'file_name': b'new.txt'})

                print(dlbf.file_name) # new.txt

        .. note::
            - Your RemoteBox will NOT know about this update,
              so you should specify here ``drb``.

            - Not a *default* metadata (default is file_name, mime, etc)
              will be placed to the ``residual_metadata`` property dict.

            - LocalBox doesn't have any limit on the CAttrs size, but in
              RemoteBox there is a file caption (and so updated metadata)
              limit: 1KB and 2KB for a Premium Telegram users. Don't
              specify ``drb`` if you want to update LocalBox only.

            - You can replace file's path by specifying a
              `file_path`` key with appropriate path (str/bytes).
        """
        if 'file_path' in changes and not dlb\
            and not isinstance(self._lb, DecryptedLocalBox):
                raise ValueError('You can\'t change file_path without specifying dlb!')

        if 'efile_path' in changes:
            raise ValueError('The "changes" should not contain efile_path')

        current_changes = changes.copy()

        logger.debug(f'Applying changes {current_changes} to the ID{self._id}...')

        dlb = dlb if dlb else self._lb
        try:
            old_updates = await dlb._tgbox_db.FILES.select_once(sql_tuple=(
                'SELECT UPDATED_METADATA FROM FILES WHERE ID=?',
                (self._id,)
            ))
            updates = AES(self._filekey).decrypt(old_updates[0])
            updates = PackedAttributes.unpack(updates)
        except (ValueError, TypeError):
            updates = {}

        new_file_path = current_changes.pop('file_path', None)
        if isinstance(new_file_path, bytes):
            new_file_path = new_file_path.decode()

        if new_file_path:
            self._directory = await dlb._make_local_path(Path(new_file_path))

            await dlb._tgbox_db.FILES.execute((
                'UPDATE FILES SET PPATH_HEAD=? WHERE ID=?',
                (self._directory.part_id, self._id)
            ))
            efile_path = AES(dlb._mainkey).encrypt(new_file_path.encode())
            current_changes['efile_path'] = efile_path

        elif new_file_path is not None:
            # User requested us to remove updated file
            # path from the LocalBox, so we need to
            # restore the original PPATH_HEAD
            self._file_path = self._original_file_path
            self._directory = await dlb._make_local_path(self._original_file_path)

            await dlb._tgbox_db.FILES.execute((
                'UPDATE FILES SET PPATH_HEAD=? WHERE ID=?',
                (self._directory.part_id, self._id)
            ))

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

        await self.refresh_metadata(_updated_metadata=updates_encoded)

        if drb:
            drbf = await drb.get_file(self._id)

        if drbf:
            await drbf.update_metadata(changes, dlb=dlb)

    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        """
        Returns ``ShareKey`` for this file. You should
        use this method if you want to share your
        ``DecryptedLocalBoxFile`` with other people.

        Arguments:
            reqkey (``RequestKey``, optional):
                Requester's ``RequestKey``. If isn't specified
                returns ``ShareKey`` of this file without
                encryption, so ANYONE with this key can
                decrypt this local & remote box file.
        """
        if reqkey:
            return make_sharekey(self._filekey, self._file_salt, reqkey)

        return make_sharekey(self._filekey)

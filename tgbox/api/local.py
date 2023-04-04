"""Module with API functions and classes for LocalBox."""

import logging

from typing import (
    BinaryIO, Union, NoReturn, Callable,
    AsyncGenerator, Dict, Optional
)
from os.path import getsize
from pathlib import Path

from os import PathLike
from io import BytesIO
from time import time

from hashlib import sha256
from asyncio import iscoroutinefunction, gather

from filetype import guess as filetype_guess
from telethon.tl.types import Photo, Document

from ..crypto import get_rnd_bytes
from ..crypto import AESwState as AES

from ..keys import (
    make_filekey, make_requestkey,
    EncryptedMainkey, make_mainkey,
    make_sharekey, MainKey, RequestKey,
    ShareKey, ImportKey, FileKey, BaseKey
)
from ..defaults import PREFIX, VERBYTE, DEF_TGBOX_NAME

from ..errors import (
    NotInitializedError, AlreadyImported,
    InUseException, AESError, PreviewImpossible,
    LimitExceeded, DurationImpossible, InvalidFile,
    NotEnoughRights, IncorrectKey, FingerprintExists
)
from ..tools import (
    PackedAttributes, ppart_id_generator,
    int_to_bytes, bytes_to_int, SearchFilter,
    get_media_duration, prbg, make_media_preview
)
from .utils import (
    DirectoryRoot, search_generator, PreparedFile,
    _TelegramVirtualFile, TelegramClient,
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
        basekey: BaseKey) -> 'DecryptedLocalBox':
    """
    Makes LocalBox

    Arguments:
        erb (``RemoteBox``):
            ``EncryptedRemoteBox``. You will
            recieve it after ``make_remotebox``.

        basekey (``BaseKey``):
            ``BaseKey`` that will be used
            for ``MainKey`` creation.
    """
    erb_box_name = await erb.get_box_name()

    logger.info(f'TgboxDB.create({erb_box_name})')
    tgbox_db = await TgboxDB.create(erb_box_name)

    if (await tgbox_db.BOX_DATA.count_rows()):
        raise InUseException(
           f'''"{tgbox_db.name}" was found on current path. '''
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
        box_salt,
        None, # We aren't cloned box, so Mainkey is empty
        AES(basekey).encrypt(erb._tc.session.save().encode()),
        AES(mainkey).encrypt(int_to_bytes(erb._tc._api_id)),
        AES(mainkey).encrypt(bytes.fromhex(erb._tc._api_hash)),
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
        return await EncryptedLocalBox(tgbox_db).decrypt(basekey)
    else:
        logger.info(f'Getting EncryptedLocalBox of {tgbox_db.db_path}')
        return await EncryptedLocalBox(tgbox_db).init()

async def clone_remotebox(
        drb: 'tgbox.api.remote.DecryptedRemoteBox',
        basekey: BaseKey,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        box_path: Optional[Union[PathLike, str]] = None) -> 'DecryptedLocalBox':
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

        box_path (``PathLike``, ``str``, optional):
            Direct path with filename included. If
            not specified, then ``RemoteBox`` name used.
    """
    drb_box_name = await drb.get_box_name()
    box_path = drb_box_name if not box_path else box_path

    logger.info(
        f'Cloning DecryptedRemoteBox {drb_box_name} to LocalBox {box_path}'
    )
    tgbox_db = await TgboxDB.create(box_path)

    if (await tgbox_db.BOX_DATA.count_rows()):
        raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

    last_file_id = 0
    async for erbf in drb.files(decrypt=False, return_imported_as_erbf=True):
        last_file_id = erbf.id; break

    await tgbox_db.BOX_DATA.insert(
        AES(drb._mainkey).encrypt(int_to_bytes(drb._box_channel_id)),
        AES(drb._mainkey).encrypt(int_to_bytes(int(time()))),
        await drb.get_box_salt(),
        AES(basekey).encrypt(drb._mainkey.key),
        AES(basekey).encrypt(drb._tc.session.save().encode()),
        AES(drb._mainkey).encrypt(int_to_bytes(drb._tc._api_id)),
        AES(drb._mainkey).encrypt(bytes.fromhex(drb._tc._api_hash)),
    )
    dlb = await EncryptedLocalBox(tgbox_db).decrypt(basekey)

    files_generator = drb.files(
        key=drb._mainkey,
        decrypt=True, reverse=True,
        erase_encrypted_metadata=False
    )
    async for drbf in files_generator:
        if progress_callback:
            if iscoroutinefunction(progress_callback):
                await progress_callback(drbf.id, last_file_id)
            else:
                progress_callback(drbf.id, last_file_id)

        logger.info(f'Importing ID{drbf.id} from {drb_box_name} to {tgbox_db.name}')
        await dlb.import_file(drbf)

    return dlb

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
    def defaults(self) -> Union[DefaultsTableWrapper, RemoteBoxDefaults]:
        """Returns ``DefaultsTableWrapper`` or ``RemoteBoxDefaults``."""
        return self._defaults

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
        logger.debug('EncryptedLocalBox initialization...')

        if not await self._tgbox_db.BOX_DATA.count_rows():
            raise NotInitializedError('Table is empty.')
        else:
            box_data = await self._tgbox_db.BOX_DATA.select_once()
            self._box_channel_id = box_data[0]
            self._box_cr_time, self._box_salt, self._mainkey = box_data[1:4]
            self._session, self._initialized = box_data[4], True
            self._api_id, self._api_hash = box_data[5], box_data[6]

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
            logger.info(f'File by ID{id} was requested from LocalBox')

            if decrypt and self._mainkey and not\
                isinstance(self._mainkey, EncryptedMainkey):
                    logger.debug(f'Trying to return ID{id} DecryptedLocalBoxFile...')

                    elbf = EncryptedLocalBoxFile(id, self._elb,
                        cache_preview=cache_preview
                    )
                    return await elbf.decrypt(dlb=self)
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
                Will **not** return LocalBoxFile associated
                with the *LocalBoxDirectory* if ``False``.
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

            min_id (``bool``, optional):
                Will iterate from this ID.

            max_id (``bool``, optional):
                Will iterate up to this ID.
        """
        min_id = f'ID >= {min_id}' if min_id else ''
        max_id = f'ID <= {max_id}' if max_id else ''

        min_id = min_id + ' AND' if all((min_id,max_id)) else min_id
        where = 'WHERE' if any((min_id, max_id)) else ''

        sql_query = f'SELECT ID FROM FILES {where} {min_id} {max_id}'
        logger.debug(sql_query)
        cursor = await self._tgbox_db.FILES.execute((sql_query ,()))

        while True:
            logger.debug('Trying to fetch new portion of local files (100)...')
            pending = await cursor.fetchmany(100)
            if not pending: return # No more files

            pending = [
                self.get_file(file_id[0], cache_preview=cache_preview)
                for file_id in pending
            ]
            pending = await gather(*pending)

            while pending:
                yield pending.pop(0)

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

        self._initialized = True

        if isinstance(key, BaseKey):
            logger.debug('BaseKey specified as key')
            if isinstance(elb._mainkey, EncryptedMainkey):
                logger.debug('Found EncryptedMainkey, decrypting...')
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
        self._api_hash = AES(self._mainkey).decrypt(elb._api_hash).hex()
        self._box_salt = elb._box_salt

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
        ppidg = ppart_id_generator(file_path, self._mainkey)

        for part, parent_part_id, part_id in ppidg:
            if not parent_part_id:
                parent_part_id = None

            logger.debug(
               f'''Adding ({part}, {parent_part_id}, {part_id}) '''
                '''to the PATH_PARTS if it\'s not already in'''
            )
            await self._tgbox_db.PATH_PARTS.insert(
                AES(self._mainkey).encrypt(part.encode()),
                part_id, parent_part_id, ignore=True
            )
        elbd = EncryptedLocalBoxDirectory(self._elb, part_id)
        return await elbd.decrypt(dlb=self)

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
            await self._tgbox_db.FILES.select_once(
                sql_tuple=('SELECT ID FROM FILES WHERE ID=?', (pf.file_id,))
            )
        except StopAsyncIteration:
            pass
        else:
            raise AlreadyImported('There is already file with same ID') from None

        eupload_time = AES(pf.filekey).encrypt(int_to_bytes(pf.upload_time))

        if pf.imported:
            logger.info(f'Adding imported PreparedFile ID{pf.file_id} to LocalBox')
            if make_filekey(self._mainkey, pf.filesalt) == pf.filekey:
                efilekey = None # We can make it with our MainKey
            else:
                efilekey = AES(self._mainkey).encrypt(pf.filekey.key)
        else:
            logger.info(f'Adding PreparedFile ID{pf.file_id} to LocalBox')
            efilekey = None

        logger.debug('Making LocalBox path parts from PreparedFile file path...')
        part_id = (await self._make_local_path(pf.filepath)).part_id

        await self._tgbox_db.FILES.insert(
            pf.file_id, eupload_time,
            part_id, efilekey, pf.fingerprint,
            pf.metadata, None
        )
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
            await self._tgbox_db.FILES.select_once(sql_tuple=(
                'SELECT ID FROM FILES WHERE FINGERPRINT=?',
                (fingerprint,)
            ))
        except StopAsyncIteration:
            pass
        else:
            raise FingerprintExists(FingerprintExists.__doc__) from None

    async def sync(
            self, drb: 'tgbox.api.remote.DecryptedRemoteBox',
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
            two parameters: (current_id, last_id).
        """
        drb_box_name = await drb.get_box_name()
        logger.info(f'Syncing {self._tgbox_db.db_path} with {drb_box_name}...')

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

        rbfiles, last_pushed_progress = [], None

        while True:
            current = 0

            if None in rbfiles:
                break

            if not rbfiles:
                rbfiles.append(await _get_file())

                if rbfiles[0] is None:
                    logger.debug('{drb_box_name} don\'t have any files, clearing local...')
                    await self._tgbox_db.FILES.execute(
                        sql_tuple=('DELETE FROM FILES', ()))
                    await self._tgbox_db.PATH_PARTS.execute(
                        sql_tuple=('DELETE FROM PATH_PARTS', ()))
                    break

                rbfiles.append(await _get_file(rbfiles[0].id))
                last_id = rbfiles[0].id

                logger.debug(
                    '''Removing all files from LocalBox which ID is less '''
                    '''than the first RemoteBox file...'''
                )
                await self._tgbox_db.FILES.execute(sql_tuple=(
                    'DELETE FROM FILES WHERE ID < ?',
                    ((await _get_file(0)).id,)
                ))
            else:
                rbfiles.append(await _get_file(rbfiles[1].id))
                if None in rbfiles: break

                rbfiles.append(await _get_file(rbfiles[2].id-1))
                if None in rbfiles: break

                rbfiles.pop(0); rbfiles.pop(1)

            while True:
                if progress_callback and last_pushed_progress != last_id:
                    if iscoroutinefunction(progress_callback):
                        await progress_callback(last_id, last_drbf_id)
                    else:
                        progress_callback(last_id, last_drbf_id)

                    last_pushed_progress = last_id

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

                if lbfi_id or 'Encrypted' in repr(rbfiles[current]):
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
                                # Imported files returned as EncryptedRemoteBoxFile,
                                # skip it as we don't have a FileKey in LocalBox
                                if 'Encrypted' in repr(rbfiles[current]):
                                    logger.debug(
                                        '''We don\'t have a FileKey to ID'''
                                       f'''{rbfiles[current].id}. Skipping.'''
                                    )
                                else:
                                    logger.debug(
                                        f'''Importing ID{rbfiles[current].id} '''
                                        f'''from {drb_box_name}'''
                                    )
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
                logger.debug(f'self._tgbox_db.FILES.execute(sql_tuple={sql_tuple})')
                await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)

            last_id = rbfiles[1].id if rbfiles[1] else None

            if last_id:
                sql_tuple = (
                    'DELETE FROM FILES WHERE ID > ? AND ID < ?',
                    (rbfiles[0].id, rbfiles[1].id)
                )
                if difference(sql_tuple[1]):
                    logger.debug(f'self._tgbox_db.FILES.execute(sql_tuple={sql_tuple})')
                    await self._tgbox_db.FILES.execute(sql_tuple=sql_tuple)
            else:
                sql_tuple = (
                    'DELETE FROM FILES WHERE ID = ?',
                    (rbfiles[0].id,)
                )
                logger.debug(f'self._tgbox_db.FILES.execute(sql_tuple={sql_tuple})')

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
            self, sf: SearchFilter,
            cache_preview: bool=True) -> AsyncGenerator[
                'DecryptedLocalBoxFile', None
            ]:
        """
        This method used to search for files in your ``DecryptedLocalBox``.

        Arguments:
            sf (``SearchFilter``):
                ``SearchFilter`` with kwargs you like.

            cache_preview (``bool``, optional):
                Will cache preview in file object if ``True``.
        """
        async for file in search_generator(
                sf, lb=self, cache_preview=cache_preview):
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

                Abs file path length must be <= ``self.defaults.FILE_PATH_MAX``;
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
        """
        file_salt, file_iv = get_rnd_bytes(32), get_rnd_bytes(16)
        filekey = make_filekey(self._mainkey, file_salt)

        if isinstance(file, (Document, Photo)):
            logger.info('Trying to make a PreparedFile from Telegram file...')

            if not self._session:
                raise NotEnoughRights(
                    '''You need to decrypt LocalBox with BaseKey, '''
                    '''MainKey is not enough. Session is None.'''
                )
            file = _TelegramVirtualFile(
                file, self._session,
                self._api_id, self._api_hash
            )
            # We will call get_preview
            make_preview = False

        if file_path is None:
            if hasattr(file,'name') and file.name:
                file_path = Path(file.name).absolute().resolve()
            else:
                file_path = Path(self._defaults.DEF_NO_FOLDER, prbg(8).hex())
        else:
            if len(file_path.parts) < 2:
                raise ValueError('Path should contain folder and file name')

            file_path = file_path.resolve()

        if len(str(file_path)) > self._defaults.FILE_PATH_MAX:
            raise LimitExceeded(f'File path must be <= {self._defaults.FILE_PATH_MAX} bytes.')

        file_fingerprint = sha256(
            str(file_path).encode()\
          + self._mainkey.key).digest()

        logger.debug(f'File fingerprint is {file_fingerprint.hex()}')

        await self._check_fingerprint(file_fingerprint)

        if not file_size:
            if isinstance(file, _TelegramVirtualFile):
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

        if file_size <= 0:
            raise InvalidFile('Specified file is empty or file_size in invalid')

        if isinstance(file, _TelegramVirtualFile):
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

        if isinstance(file, _TelegramVirtualFile):
            preview = await file.get_preview()
            duration = file.duration
        else:
            if make_preview and file_type in ('audio','video','image'):
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

        logger.debug(f'Constructing metadata for {file.name}')

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
            file_fingerprint = file_fingerprint,
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
        constructed_metadata += metadata + file_iv

        total_file_size = len(constructed_metadata) + file_size

        return PreparedFile(
            dlb = self,
            file = file,
            filekey = filekey,
            filesize = total_file_size,
            filepath = Path(file_path_no_name.decode()),
            filesalt = file_salt,
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
            if drbf.file_path:
                file_path = drbf.file_path
            else:
                logger.debug(f'ID{drbf.id} doesn\'t have file_path. Set DEF_NO_FOLDER.')
                file_path = self._defaults.DEF_NO_FOLDER

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
            fingerprint = drbf._fingerprint,
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
                    elbd = EncryptedLocalBoxDirectory(self._lb._elb, folder_row[1])
                    yield await elbd.decrypt(dlb=self._lb)
                else:
                    yield await EncryptedLocalBoxDirectory(self._lb,
                        folder_row[1]).init()

        if not ignore_files:
            files = await self._tgbox_db.FILES.execute((
                'SELECT * FROM FILES WHERE PPATH_HEAD IS ?',
                (part_id,)
            ))
            async for file_row in files:
                yield await self._lb.get_file(
                    file_row[0], cache_preview=cache_preview)

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
        Will delete this folder with all files from your LocalBox.
        All files will stay in ``RemoteBox``, so you can restore
        all your folders by importing files.
        """
        logger.debug(f'DELETE FROM FILES WHERE PPATH_HEAD={self._part_id}')
        await self._tgbox_db.FILES.execute(
            ('DELETE FROM FILES WHERE PPATH_HEAD=?',(self._part_id,))
        )
        logger.debug(f'DELETE FROM PATH_PARTS WHERE PART_ID={self._part_id}')
        await self._tgbox_db.PATH_PARTS.execute(
            ('DELETE FROM PATH_PARTS WHERE PART_ID=?',(self._part_id,))
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

        self._initialized = False
        self._fingerprint = None
        self._updated_metadata = None

        self._ppath_head, self._upload_time = None, None
        self._metadata, self._directory = None, None
        self._imported, self._efilekey = None, None
        self._file_salt, self._version_byte = None, None

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
    def file_salt(self) -> Union[bytes, None]:
        """
        Returns file salt or ``None``
        if file wasn't initialized
        """
        return self._file_salt

    @property
    def box_salt(self) -> Union[bytes, None]:
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
        self._metadata = file_row.pop()
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

        self._prefix = self._metadata[:len(PREFIX)]
        self._version_byte = self._metadata[
            len(PREFIX) : len(VERBYTE) + len(PREFIX)
        ]
        pattr_offset = len(PREFIX) + len(VERBYTE) + 3

        unpacked_metadata = PackedAttributes.unpack(
            self._metadata[pattr_offset:-16]
        )
        self._file_iv = self._metadata[-16:]
        self._file_salt = unpacked_metadata['file_salt']
        self._box_salt = unpacked_metadata['box_salt']

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
            self, key: Optional[Union[FileKey, MainKey]] = None,
            dlb: Optional[DecryptedLocalBox] = None) -> 'DecryptedLocalBoxFile':
        """
        Returns decrypted by ``key``/``dlb`` ``EncryptedLocalBoxFile``

        Arguments:
            key (``FileKey``, ``MainKey``):
                Decryption key. Must be specified if
                ``dlb`` argument is ``None``.

            dlb (``DecryptedLocalBox``, optional):
                Decrypted LocalBox. Must be specified
                if ``key`` argument is ``None``.
        """
        if not any((key, dlb)):
            raise ValueError('You should specify at least key or dlb')

        if not self.initialized:
            await self.init()

        return DecryptedLocalBoxFile(self, key=key, dlb=dlb)

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
        file_row = await self._lb._tgbox_db.FILES.select_once(
            sql_tuple=('SELECT PPATH_HEAD FROM FILES WHERE ID=?',(self._id,))
        )
        logger.debug(f'Removing ELBF | DELETE FROM FILES WHERE ID={self._id}')
        # Removing requested file
        await self._lb._tgbox_db.FILES.execute(
            ('DELETE FROM FILES WHERE ID=?',(self._id,))
        )
        ppath_head = file_row[0]
        # The code below will check all parent path part ids
        # and remove empty ones (which doesn't pointed)
        while True:
            # Retrieve file rows that point to PPATH_HEAD
            files_pointed = await self._lb._tgbox_db.FILES.execute((
                'SELECT ID FROM FILES WHERE PPATH_HEAD=?',(ppath_head,)
            ))
            if (await files_pointed.fetchone()):
                break # Part ID pointed by file, so break

            # Amount of parts that point to current ppath_head
            pparts_pointed = await self._lb._tgbox_db.PATH_PARTS.execute((
                'SELECT * FROM PATH_PARTS WHERE PARENT_PART_ID=?',
                (ppath_head,)
            ))
            if (await pparts_pointed.fetchone()):
                break

            parent_part_id = await self._lb._tgbox_db.PATH_PARTS.select_once(sql_tuple=(
                'SELECT PARENT_PART_ID FROM PATH_PARTS WHERE PART_ID=?',
                (ppath_head,)
            ))
            logger.debug(
                '''Removing orphaned directory | DELETE FROM '''
               f'''PATH_PARTS WHERE PART_ID={ppath_head}'''
            )
            await self._lb._tgbox_db.PATH_PARTS.execute((
                'DELETE FROM PATH_PARTS WHERE PART_ID=?',
                (ppath_head,)
            ))
            # Set parent part id as ppath_head to recursive
            # check for useless path parts
            ppath_head = parent_part_id[0]
            if not ppath_head: break

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
            cache_preview: bool=True):
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
                Cache preview in class or not.
        """
        if not any((key, dlb)):
            raise ValueError('At least key or dlb must be specified')

        if not elbf._initialized:
            raise NotInitializedError('You should init elbf firstly')

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

        if cache_preview is None:
            self._cache_preview = elbf._cache_preview
        else:
            self._cache_preview = cache_preview


        if isinstance(key, (FileKey, ImportKey)):
            logger.debug('Treating key as FileKey')
            self._filekey = FileKey(key.key)

        elif isinstance(key, MainKey) and self._efilekey:
            logger.debug('Trying to decrypt encrypted FileKey with MainKey')
            self._filekey = FileKey(
                AES(self._key).decrypt(self._efilekey)
            )
        elif isinstance(self._lb, DecryptedLocalBox) and self._efilekey:
            logger.debug('Trying to decrypt encrypted FileKey with DecryptedLocalBox')
            self._filekey = FileKey(
                AES(self._lb._mainkey).decrypt(self._efilekey)
            )
        elif isinstance(key, MainKey) and not self._efilekey:
            logger.debug('Making FileKey from the MainKey and FileSalt')
            self._filekey = make_filekey(self._key, self._file_salt)

        elif isinstance(self._lb, DecryptedLocalBox):
            logger.debug('We will use MainKey from DecryptedLocalBox')
            self._filekey = make_filekey(self._lb._mainkey, self._file_salt)


        if isinstance(key, MainKey):
            logger.debug('key is MainKey, self._mainkey is present')
            self._mainkey = key

            logger.debug('Decrypting EncryptedLocalBox with MainKey')
            self._lb = DecryptedLocalBox(self._lb, self._mainkey)

        elif isinstance(self._lb, DecryptedLocalBox):
            self._mainkey = self._lb._mainkey
        else:
            self._mainkey = None

        self._upload_time = AES(self._filekey).decrypt(elbf._upload_time)
        self._upload_time = bytes_to_int(self._upload_time)

        pattr_offset = len(PREFIX) + len(VERBYTE) + 3

        logger.debug(f'Unpacking public metadata of ID{self._id}...')

        unpacked_metadata = PackedAttributes.unpack(
            self._elbf._metadata[pattr_offset:-16]
        )

        logger.debug(f'Decrypting & unpacking secret metadata of ID{self._id}...')

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

        self._size = bytes_to_int(self._file_size) # pylint: disable=no-member
        del self._file_size # pylint: disable=no-member

        self._duration = bytes_to_int(self._duration)
        self._cattrs = PackedAttributes.unpack(self._cattrs)
        self._mime = self._mime.decode()

        self._file_name = self._file_name.decode()

        if not cache_preview:
            self._preview = b''

        if self._mainkey and not self._efilekey:
            logger.debug('Decrypting efile_path with the MainKey')
            self._file_path = AES(self._mainkey).decrypt(
                secret_metadata['efile_path']
            )
            self._file_path = Path(self._file_path.decode())
        else:
            logger.warning(
               f'''We can\'t decrypt real file path of ID{self._id} because '''
                '''MainKey is not present. Try to decrypt EncryptedLocalBoxFile '''
                '''with MainKey to fix this. Setting to DEF_NO_FOLDER...'''
            )
            self._file_path = self._defaults.DEF_NO_FOLDER

        for attr in self.__required_metadata:
            secret_metadata.pop(attr)

        self._residual_metadata = secret_metadata

        if self._mainkey:
            self._directory = DecryptedLocalBoxDirectory(
                self._elbf._directory, dlb=self._lb
            )
        else:
            self._directory = self._elbf._directory

        self._download_path = self._defaults.DOWNLOAD_PATH

        if self._elbf._updated_metadata:
            logger.debug(f'Updates to metadata for ID{self._id} found. Applying...')

            updates = AES(self._filekey).decrypt(
                self._elbf._updated_metadata
            )
            updates = PackedAttributes.unpack(updates)

            for k,v in tuple(updates.items()):
                if k in self.__required_metadata:
                    if k == 'cattrs':
                        setattr(self, f'_{k}', PackedAttributes.unpack(v))

                    elif k == 'file_name':
                        setattr(self, f'_{k}', v.decode())

                    elif k == 'efile_path':
                        if self._mainkey and not self._efilekey:
                            self._file_path = AES(self._mainkey).decrypt(v)
                            self._file_path = Path(self._file_path.decode())
                        else:
                            self._file_path = self._defaults.DEF_NO_FOLDER
                    else:
                        setattr(self, f'_{k}', v)
                else:
                    self._residual_metadata[k] = v

        self._elbf._initialized = False
        self._elbf._metadata = None # To save RAM
        self._elbf._updated_metadata = None

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

    def set_download_path(self, path: Path):
        """Will set download path to specified."""
        self._download_path = path

    async def refresh_metadata(
            self, drb: Optional['tgbox.api.remote.DecryptedRemoteBox'] = None,
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

        logger.debug(
            '''Updating metadata | UPDATE FILES SET '''
           f'''UPDATED_METADATA={_updated_metadata} '''
           f'''WHERE ID={self._id}'''
        )
        await self._lb._tgbox_db.FILES.execute((
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

"""Module with some magic high-level API functions and classes of TGBOX."""

import logging

from os import PathLike
from asyncio import gather
from typing import Optional, Union, NoReturn

from .local import (
    DecryptedLocalBox, make_localbox,
    get_localbox, DecryptedLocalBoxFile,
    EncryptedLocalBoxFile
)
from .remote import (
    DecryptedRemoteBox, make_remotebox, get_remotebox
)
from .utils import syncify, TelegramClient

from ..defaults import (
    DEF_TGBOX_NAME, REMOTEBOX_PREFIX, BOX_IMAGE_PATH
)
from ..errors import NotInitializedError, InvalidFile
from ..keys import BaseKey
from ..crypto import BoxSalt


logger = logging.getLogger(__name__)

async def make_box(
        tc: TelegramClient,
        basekey: BaseKey,

        box_name: Optional[str] = DEF_TGBOX_NAME,
        rb_prefix: Optional[str] = REMOTEBOX_PREFIX,
        box_image: Optional[Union[PathLike, str]] = BOX_IMAGE_PATH,
        box_path: Optional[Union[PathLike, str]] = None,
        box_salt: Optional[BoxSalt] = None) -> 'Box':
    """
    Makes Box object. See ``help(tgbox.api.abstract.Box)``

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
    erb = await make_remotebox(
        tc=tc, box_name=box_name, rb_prefix=rb_prefix,
        box_image=box_image, box_salt=box_salt
    )
    dlb = await make_localbox(
        erb=erb, basekey=basekey,
        box_name=box_name, box_path=box_path
    )
    drb = await erb.decrypt(dlb=dlb)
    return Box(dlb=dlb, drb=drb)

async def get_box(basekey: BaseKey,
        tgbox_db_path: Optional[Union[PathLike, str]] = DEF_TGBOX_NAME,
        proxy: Optional[Union[tuple, list, dict]] = None) -> 'Box':
    """
    Return Box object. See ``help(tgbox.api.abstract.Box)``

    Arguments:
        basekey (``BaseKey``):
            *BaseKey* of your ``Box``

        tgbox_db_path (``PathLike``, ``str``, optional):
            ``PathLike`` to your TgboxDB (LocalBox). Default
            is ``defaults.DEF_TGBOX_NAME``.

        proxy (tuple, list, dict, optional):
            An iterable consisting of the proxy info. If connection
            is one of MTProxy, then it should contain MTProxy credentials:
            ('hostname', port, 'secret'). Otherwise, it’s meant to store
            function parameters for PySocks, like (type, 'hostname', port).
            See https://github.com/Anorov/PySocks#usage-1 for more info.
    """
    dlb = await get_localbox(basekey=basekey, tgbox_db_path=tgbox_db_path)
    drb = await get_remotebox(dlb=dlb, proxy=proxy)
    return Box(dlb=dlb, drb=drb)


class Box(DecryptedLocalBox):
    """
    The ``abstract.Box`` is an object that contains the methods from
    both ``DecryptedLocalBox`` and ``DecryptedRemoteBox`` classes.

    Where possible, we try to use the methods from the *LocalBox*
    to take off unnecessary load, however, the ``BoxFile`` objects
    that ``Box`` return (for example from ``get_file()`` or ``files()``
    or ``search_file()`` **always** make requests & downloads info
    from your *RemoteBox* (Telegram Channel). If you want to get
    data from your *LocalBox* only, then you can use a ``Box.dlb`` or
    similarly ``Box.drb`` for the *RemoteBox* only features.

    .. tip::
        To understand more about the TGBOX Protocol you can use a
        ``help()`` on every class/method from the ``tgbox.api``
        package and Read The Docs: tgbox.readthedocs.io/en/latest/

    Usage:

    .. code-block:: python

        import asyncio
        import tgbox

        async def main():
            box = await tgbox.get_box(tgbox.keys.make_basekey(b'OZZY'))
            bf = await box.get_file(await box.get_last_file_id())

            print(bf.id, bf.file_name, bf.directory)
            await bf.download() # Download Box file

            await box.done() # Close all connections

        asyncio.run(main())

    Smart usage of DLB & DRB:

    .. code-block:: python

        '''
        In this example on file searching we load files
        from the LocalBox, thus no requests to the Telegram
        servers. Only if file match our SearchFilter we
        download information from RemoteBox and then
        download file. On other hand, the Box class
        itself has the ``search_file()`` method, but it
        loads *every single file* from servers. We don't
        need this, as searching will be slow and pricey.

        You may encounter such situations, don't hesitate
        to use the DLB or DRB directly on need :)
        '''

        import asyncio
        import tgbox

        async def main():
            box = await tgbox.get_box(tgbox.keys.make_basekey(b'OZZY'))

            sf = tgbox.tools.SearchFilter(
                scope='/home/user/Music',
                file_path='Black Rain',
                mime='audio'
            )
            async for dlbf in box.dlb.search_file(sf):
                drbf = await box.drb.get_file(dlbf.id)
                await drbf.download()

            await box.done() # Close all connections

        asyncio.run(main())
    """
    def __init__(self, dlb: DecryptedLocalBox, drb: DecryptedRemoteBox):
        """
        Arguments:
            dlb (``DecryptedLocalBox``):
                The ``DecryptedLocalBox`` object! Also Yin...

            drb (``DecryptedRemoteBox``):
                The ``DecryptedRemoteBox`` object! Also Yang...
        """
        if not (dlb.box_channel_id == drb.box_channel_id):
            raise NotInitializedError('Box ID mismatch!')

        super().__init__(dlb._elb, dlb._mainkey)

        self.dlb = dlb
        self.drb = drb

        # Methods from the DecryptedRemoteBox
        self.tc = self.drb.tc
        self.box_channel = self.drb.box_channel
        self.file_exists = self.drb.file_exists

        self.push_file = self.drb.push_file
        self.update_file = self.drb.update_file
        self.left = self.drb.left

        # Here we Syncify inherited methods of super()
        if getattr(self, '_needs_syncify', None):
            syncify(self); self._needs_syncify = False # pylint: disable=W0201

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({repr(self.dlb)}, {repr(self.drb)})'

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({str(self.dlb)}, {str(self.drb)})'

    async def is_synced(self) -> bool:
        """
        This method will compare Last file ID of
        RemoteBox with Last file ID of LocalBox,
        if the same, -- will return True.

        Please note that it's not guaranteed to be
        right, as changes can be made not only to
        the last files in Box. If you share your
        Box with someone else, then consider to
        use ``Box.sync()`` method more often.
        """
        lfid_remote = await self.drb.get_last_file_id()
        lfid_local = await self.dlb.get_last_file_id()
        return lfid_remote == lfid_local

    async def get_file(
            self, id: int, cache_preview: bool=True,
            erase_encrypted_metadata: bool=True,
            decrypt: Optional[None] = None) -> 'BoxFile':
        """
        This method returns ``BoxFile`` object, which
        class contains the methods from the both of
        ``DecryptedLocalBoxFile`` and ``DecryptedRemoteBoxFile``.

        .. tip::
            You may want to get file information **only**. For
            such case use the same method on the ``Box.dlb``.

        Arguments:
            id (``int``):
                Box file ID.

            cache_preview (``bool``, optional):
                Cache preview in class or not.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata to save more RAM if ``True``.

            decrypt (``bool``, optional):
                Guess what? Does nothing! Inherited methods
                like ``files()`` expect this kwarg, but here
                we don't need it at all. Ignored.
        """
        bf = BoxFile(id, dlb=self.dlb, drb=self.drb,
            cache_preview=cache_preview,
            erase_encrypted_metadata=erase_encrypted_metadata
        )
        return await bf.init()

    async def delete_files(self, *args, **kwargs):
        """
        See ``help(DecryptedRemoteBox.delete_files)``.
        ``lb`` is auto passed to ``delete_files()``.
        """
        return await self.drb.delete_files(*args, **kwargs, lb=self.dlb)

    async def sync(self, *args, **kwargs):
        """
        See ``help(DecryptedLocalBox.sync)``.
        ``drb`` is auto passed to ``sync()``.
        """
        return await self.dlb.sync(*args, **kwargs, drb=self.drb)

    async def done(self):
        """
        Await this method when you end all
        work with Box, so we will
        clean up & close connections.
        """
        await self.dlb.done()
        await self.drb.done()


class BoxFile(DecryptedLocalBoxFile):
    """
    The ``abstract.BoxFile`` is an object that contains the methods from
    both ``DecryptedLocalBoxFile`` and ``DecryptedRemoteBoxFile`` classes.

    Where possible, we try to use the methods from the *LocalBoxFile*
    to take off unnecessary load. You can access ``BoxFile.dlb``,
    ``BoxFile.drb``, ``BoxFile.dlbf`` and ``BoxFile.drbf``
    from this class if you need to use methods explicitly.

    .. note::
        This class must be initialized firstly via ``init() coro.``

    .. tip::
        To understand more about the TGBOX Protocol you can use a
        ``help()`` on every class/method from the ``tgbox.api``
        package and Read The Docs: tgbox.readthedocs.io/en/latest/
    """
    def __init__(
            self, id: int, dlb: DecryptedLocalBox, drb: DecryptedRemoteBox,
            cache_preview: bool=True, erase_encrypted_metadata=True):
        """
        Arguments:
            id (``int``):
                Box file ID.

            dlb (``DecryptedLocalBox``):
                The ``DecryptedLocalBox`` object! Also Yin...

            drb (``DecryptedRemoteBox``):
                The ``DecryptedRemoteBox`` object! Also Yang...

            cache_preview (``bool``, optional):
                Cache preview in class or not.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata to save more RAM if ``True``.
        """
        self.__initialized = False

        self.__id = id
        self.dlb = dlb
        self.drb = drb

        self.dlbf = None
        self.drbf = None

        self.cache_preview = cache_preview
        self.erase_encrypted_metadata = erase_encrypted_metadata

        # Methods from the DecryptedRemoteBoxFile will be initialized
        # after(/inside) the BoxFile.init() call. Otherwise None.
        self.download = None
        self.sender = None
        self.file = None
        self.message = None
        self.file_size = None
        self.file_file_name = None
        self.box_channel = None

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__} @ {self.dlbf=}, {self.drbf=}'

    def __str__(self) -> str:
        return repr(self)

    def __raise_initialized(self) -> NoReturn:
        if not self.__initialized:
            raise NotInitializedError('Not initialized. Call .init().')

    @property
    def initialized(self) -> bool:
        """Returns ``True`` if you called ``.init()``"""
        return self.__initialized

    async def init(self) -> 'BoxFile':
        """
        Will initialize ``BoxFile`` object. Part of
        initialization is downloading information
        about file from the Telegram servers. If
        you don't want this, -- use ``Box.dlb``.

        You can't access DLBF/DRBF methods before
        the initialization. Call this firstly.
        """
        logger.debug('DLBF+DRBF initialization...')

        elbf = EncryptedLocalBoxFile(
            id=self.__id, elb=self.dlb._elb,
            cache_preview=self.cache_preview)

        await elbf.init()

        super().__init__(elbf=elbf, dlb=self.dlb, cache_preview=self.cache_preview,
            erase_encrypted_metadata=self.erase_encrypted_metadata)

        self.dlbf, self.drbf = await gather(
            self.dlb.get_file(self.id, cache_preview=self.cache_preview),
            self.drb.get_file(self.id, cache_preview=self.cache_preview)
        )
        if not all((self.dlbf, self.drbf)):
            raise InvalidFile('Your Box is out of Sync! Use .sync(deep=True)')

        self.download = self.drbf.download
        self.sender = self.drbf.sender
        self.file = self.drbf.file
        self.message = self.drbf.message
        self.file_size = self.drbf.file_size
        self.file_file_name = self.drbf.file_file_name
        self.box_channel = self.drbf.box_channel

        if getattr(self, '_needs_syncify', None):
            # Here we Syncify inherited methods of super()
            syncify(self); self._needs_syncify = False # pylint: disable=W0201

        self.__initialized = True
        return self

    async def update_metadata(self, *args, **kwargs):
        """
        See ``help(DecryptedRemoteBoxFile.update_metadata)``.
        ``dlb`` is auto passed to ``update_metadata()``.
        """
        self.__raise_initialized()
        return await self.drbf.update_metadata(
            *args, **kwargs, dlb=self.dlb)

    async def delete(self, remote: Optional[bool] = False, *args, **kwargs):
        """
        See ``help(DecryptedLocalBoxFile.delete)`` &
        see ``help(DecryptedRemoteBoxFile.delete)``.

        If ``remote`` is ``True``, will be called the same
        method on the ``DecryptedRemoteBoxFile``, deleting
        file in the Local & Remote Box. Do NOT set this
        kwarg to ``True`` if you don't want to completly
        destroy and remove your uploaded file from Box.
        """
        self.__raise_initialized()
        await self.dlbf.delete(*args, **kwargs)
        if remote:
            await self.drbf.delete(*args, **kwargs)

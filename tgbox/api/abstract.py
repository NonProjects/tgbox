"""Module with some magic high-level API functions and classes of TGBOX."""

import logging

from os import PathLike
from asyncio import gather

from typing import (
    Optional, Union, NoReturn,
    BinaryIO, Callable, List
)
from .local import (
    DecryptedLocalBox, make_localbox,
    get_localbox, DecryptedLocalBoxFile,
    EncryptedLocalBoxFile
)
from .remote import (
    DecryptedRemoteBox, DecryptedRemoteBoxFile,
    make_remotebox, get_remotebox
)
from .utils import (
    syncify, TelegramClient, TelegramVirtualFile
)
from ..defaults import (
    DEF_TGBOX_NAME, REMOTEBOX_PREFIX, BOX_IMAGE_PATH
)
from ..errors import NotInitializedError, InvalidFile
from ..keys import BaseKey
from ..crypto import BoxSalt

__all__ = ['make_box', 'get_box', 'Box', 'BoxFile']

logger = logging.getLogger(__name__)

async def make_box(
        tc: TelegramClient,
        basekey: BaseKey,

        box_name: Optional[str] = DEF_TGBOX_NAME,
        rb_prefix: Optional[str] = REMOTEBOX_PREFIX,
        box_image: Optional[Union[PathLike, str]] = BOX_IMAGE_PATH,
        box_path: Optional[Union[PathLike, str]] = None,
        box_salt: Optional[BoxSalt] = None,
        lazy_files: Optional[bool] = False) -> 'Box':
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

        lazy_files (``bool``, optional):
            If ``True``, files returned by this ``Box`` will **not**
            load ``DecryptedRemoteBoxFile`` until the ``load_drbf``
            method will be called on target ``BoxFile``. Should be
            useful if you only want to fetch information about files.

            You can "lazy" files via ``make_files_lazy()`` and "unlazy"
            via ``make_files_unlazy()`` method respectively (on ``Box``).
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
    return Box(dlb=dlb, drb=drb, lazy_files=lazy_files)

async def get_box(basekey: BaseKey,
        tgbox_db_path: Optional[Union[PathLike, str]] = DEF_TGBOX_NAME,
        proxy: Optional[Union[tuple, list, dict]] = None,
        lazy_files: Optional[bool] = False) -> 'Box':
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

        lazy_files (``bool``, optional):
            If ``True``, files returned by this ``Box`` will **not**
            load ``DecryptedRemoteBoxFile`` until the ``load_drbf``
            method will be called on target ``BoxFile``. Should be
            useful if you only want to fetch information about files.

            You can "lazy" files via ``make_files_lazy()`` and "unlazy"
            via ``make_files_unlazy()`` method respectively (on ``Box``).
    """
    dlb = await get_localbox(basekey=basekey, tgbox_db_path=tgbox_db_path)
    drb = await get_remotebox(dlb=dlb, proxy=proxy)
    return Box(dlb=dlb, drb=drb, lazy_files=lazy_files)


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

    Also, you can set a ``lazy_files`` kwarg to ``True`` so file
    obtaining methods will return a "Lazy" ``BoxFile`` objects.

    "Lazy" ``BoxFile`` will **not** load ``DecryptedRemoteBoxFile``
    until the ``load_drbf()`` call, thus, can be useful for only
    retrieving information about files without need to use a
    ``Box.dlb`` ``DecryptedLocalBox`` object.

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


    Or just use a 'lazy_files' kwarg!:

    .. code-block:: python

        import asyncio
        import tgbox

        async def main():
            box = await tgbox.get_box(
                basekey = tgbox.keys.make_basekey(b'OZZY'),
                lazy_files = True
            )
            sf = tgbox.tools.SearchFilter(
                scope='/home/user/Music',
                file_path='Black Rain',
                mime='audio'
            )
            async for bf in box.search_file(sf):
                await bf.load_drbf()
                await bf.download()

            await box.done() # Close all connections

        asyncio.run(main())
    """
    def __init__(self, dlb: DecryptedLocalBox, drb: DecryptedRemoteBox,
            lazy_files: Optional[bool] = False):
        """
        Arguments:
            dlb (``DecryptedLocalBox``):
                The ``DecryptedLocalBox`` object! Also Yin...

            drb (``DecryptedRemoteBox``):
                The ``DecryptedRemoteBox`` object! Also Yang...

            lazy_files (``bool``, optional):
                If ``True``, files returned by this ``Box`` will **not**
                load ``DecryptedRemoteBoxFile`` until the ``load_drbf``
                method will be called on target ``BoxFile``. Should be
                useful if you only want to fetch information about files.

                You can "lazy" files via ``make_files_lazy()`` and "unlazy"
                via ``make_files_unlazy()`` method respectively.
        """
        if not isinstance(dlb, DecryptedLocalBox):
            raise TypeError('dlb must be DecryptedLocalBox')

        if not isinstance(drb, DecryptedRemoteBox):
            raise TypeError('drb must be DecryptedRemoteBox')

        if not (dlb.box_channel_id == drb.box_channel_id):
            raise NotInitializedError('Box ID mismatch!')

        super().__init__(dlb._elb, dlb._mainkey)

        self.dlb = dlb
        self.drb = drb

        self.lazy_files = lazy_files

        # Methods from the DecryptedRemoteBox
        self.tc = self.drb.tc
        self.box_channel = self.drb.box_channel
        self.file_exists = self.drb.file_exists
        self.push_file = self.drb.push_file
        self.update_file = self.drb.update_file
        self.left = self.drb.left

        self.get_box_description = self.drb.get_box_description
        self.get_box_name = self.drb.get_box_name

        if getattr(self, '_needs_syncify', None):
            syncify(self) # Here we Syncify inherited methods of super()

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({repr(self.dlb)}, {repr(self.drb)})'

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({str(self.dlb)}, {str(self.drb)})'

    def make_files_lazy(self) -> None:
        """
        Will make files that this ``Box`` output 'Lazy'
        (Lazy files don't load DRBF until ``load_drbf()``)
        """
        self.lazy_files = True

    def make_files_unlazy(self) -> None:
        """
        Will make files that this ``Box`` output 'Unlazy'
        (Unlazy files load DRBF without ``load_drbf()``)
        """
        self.lazy_files = False

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
            decrypt: Optional[None] = None,
            lazy: Optional[bool] = None) -> 'BoxFile':
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

            lazy (``bool``, optional):
                Lazy files don't load DRBF until ``load_drbf()``
                is called. If ``None``, will use ``self.lazy_files``
        """
        bf = BoxFile(id=id, dlb=self.dlb, drb=self.drb,
            cache_preview=cache_preview,
            erase_encrypted_metadata=erase_encrypted_metadata,
            lazy=(lazy if lazy is not None else self.lazy_files)
        )
        return await bf.init()

    async def delete_files(self, remote: Optional[bool] = False, *args, **kwargs):
        """
        See ``help(DecryptedLocalBox.delete_files)`` &
        see ``help(DecryptedRemoteBox.delete_files)``.

        If ``remote`` is ``True``, will be called the same
        method on the ``DecryptedRemoteBox``, deleting
        files in the Local & Remote Box. Do NOT set this
        kwarg to ``True`` if you don't want to completly
        destroy and remove selected files from Box.

        ``rb`` is auto passed to ``delete_files()`` and
        is ``None`` if ``remote`` is ``False``.
        """
        await self.dlb.delete_files(*args, **kwargs,
            rb=(self.drb if remote else None)
        )
    async def sync(self, *args, **kwargs):
        """
        See ``help(DecryptedLocalBox.sync)``.
        ``drb`` is auto passed to ``sync()``.
        """
        return await self.dlb.sync(*args, **kwargs, drb=self.drb)

    async def push(self, file: Union[str, BinaryIO, bytes, TelegramVirtualFile, list],
            progress_callback: Optional[Callable[[int, int], None]] = None,
            use_slow_upload: Optional[bool] = False, *args, **kwargs
            ) -> Union['BoxFile', List['BoxFile']]:
        """
        This is a wrapper around ``DecryptedRemoteBox.push_file``. Will
        automatically use ``DecryptedLocalBox.prepare_file``. See
        ``help()`` on both of these methods for additional arguments.

        Arguments:
            file (``str``, ``BinaryIO``, ``bytes``, ``TelegramVirtualFile``, ``list``):
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

                We will treat this argument as path to file and
                auto ``open()`` here if it is specified as ``str``.

                This argument accept ``list`` of ``file`` for uploading
                files simultaneously. DO NOT specify too many big files!
                Otherwise you may receive 429 -- ``FloodWaitError``.

                .. note::
                    This argument will be auto passed to ``prepare_file()``

            progress_callback (``Callable[[int, int], None]``, optional):
                A callback function accepting two parameters:
                (downloaded_bytes, total). A ``push_file`` kwarg.

            use_slow_upload (``bool``, optional):
                Will use default upload function from the Telethon
                library instead of function from `fastelethon.py`.
                Use this if you have problems with upload. A
                ``push_file`` kwarg.

            .. note::
                The ``*args`` and ``**kwargs`` will be redirected only
                to the ``DecryptedLocalBox.prepare_file`` method. See
                ``help(DecryptedLocalBox.prepare_file)`` for kwargs.

        Returns:
            A single ``BoxFile`` object or a ``list`` with ``BoxFile``
            objects if ``file`` was specified as ``list`` with files.
        """
        file = [file,] if not isinstance(file, list) else file
        file = [(open(f,'rb') if isinstance(f, str) else f) for f in file]

        file_ = []
        while file:
            file_.append( # Make a PreparedFile objects
                self.dlb.prepare_file(
                    file=file.pop(0), *args, **kwargs)
            )
        file = await gather(*file_)

        file_ = []
        while file:
            file_.append( # Get a DecryptedRemoteBoxFile objects
                self.drb.push_file(
                    pf=file.pop(0),
                    progress_callback=progress_callback,
                    use_slow_upload=use_slow_upload
                )
            )
        file_drbf = await gather(*file_)

        file_dlbf = [ # Get a DecryptedLocalBoxFile objects from DRBF
            self.dlb.get_file(drbf.id, erase_encrypted_metadata=False)
            for drbf in file_drbf
        ]
        file_dlbf = await gather(*file_dlbf)

        abbf_list = [] # Union DLBF & DRBF into BoxFile
        for drbf, dlbf in zip(file_drbf, file_dlbf):
            abbf_list.append(BoxFile(dlbf=dlbf, drbf=drbf).init())

        abbf_list = await gather(*abbf_list)
        if len(abbf_list) == 1:
            return abbf_list[0]

        return abbf_list

    async def delete(self, remote: Optional[bool] = False, *args, **kwargs):
        """
        This method **WILL DELETE** *Box*!

        See ``help(DecryptedLocalBox.delete)`` &
        see ``help(DecryptedRemoteBox.delete)``.

        If ``remote`` is ``True``, will be called the same
        method on the ``DecryptedRemoteBox``, completly
        deleting **ALL OF YOUR FILES AND BOX INFORMATION!**

        Use ``left()`` if you **only want to left**
        your *Box* ``Channel``, not destroy it.
        """
        await self.dlb.delete(*args, **kwargs)
        if remote:
            await self.drb.delete(*args, **kwargs)

    async def done(self):
        """
        Await this method when you end all
        work with Box, so we will
        clean up & close connections.
        """
        await gather(self.dlb.done(), self.drb.done())

class BoxFile(DecryptedLocalBoxFile):
    """
    The ``abstract.BoxFile`` is an object that contains the methods from
    both ``DecryptedLocalBoxFile`` and ``DecryptedRemoteBoxFile`` classes.

    Where possible, we try to use the methods from the *LocalBoxFile*
    to take off unnecessary load. You can access ``BoxFile.dlb``,
    ``BoxFile.drb``, ``BoxFile.dlbf`` and ``BoxFile.drbf``
    from this class if you need to use methods explicitly.

    ``BoxFile`` can be "Lazy". Such objects don't load the
    ``DecryptedLocalBoxFile`` until ``load_drbf()`` call.

    .. note::
        This class must be initialized firstly via ``init() coro.``

    .. tip::
        To understand more about the TGBOX Protocol you can use a
        ``help()`` on every class/method from the ``tgbox.api``
        package and Read The Docs: tgbox.readthedocs.io/en/latest/
    """
    def __init__(self,
            id: Optional[int] = None,
            dlb: Optional[DecryptedLocalBox] = None,
            drb: Optional[DecryptedRemoteBox] = None,

            dlbf: Optional[DecryptedLocalBoxFile] = None,
            drbf: Optional[DecryptedRemoteBoxFile] = None,

            cache_preview: Optional[bool] = True,
            erase_encrypted_metadata: Optional[bool] = True,
            lazy: Optional[bool] = False):
        """
        Arguments:
            id (``int``):
                Box file ID. Must be specified if ``dlbf``
                and ``drbf`` is ``None``.

            dlb (``DecryptedLocalBox``):
                The ``DecryptedLocalBox`` object! Also Yin...
                Must be specified if ``dlbf`` and ``drbf`` is ``None``

            drb (``DecryptedRemoteBox``):
                The ``DecryptedRemoteBox`` object! Also Yang...
                Must be specified if ``dlbf`` and ``drbf`` is ``None``


            dlbf (``DecryptedLocalBoxFile``):
                The ``DecryptedLocalBoxFile`` object! Also Yin...
                Must be specified if ``id``, ``dlb``
                and ``drbf`` is ``None``

            drbf (``DecryptedRemoteBoxFile``):
                The ``DecryptedRemoteBoxFile`` object! Also Yang...
                Must be specified if ``id``, ``dlb``
                and ``drbf`` is ``None``

            cache_preview (``bool``, optional):
                Cache preview in class or not.

            erase_encrypted_metadata (``bool``, optional):
                Will remove metadata to save more RAM if ``True``.

            lazy (``bool``, optional):
                If ``True``, will **not** load ``DecryptedRemoteBoxFile``
                until ``load_drbf()`` method call. Should be useful
                if you only want to *fetch* information, not download.

                All DRBF-related methods will be ``None`` if ``lazy``
                until you call ``load_drbf()`` method.

        .. note::
            Must be specified ``id``, ``dlb`` and ``drb`` or
            ``dlbf`` and ``drbf``. Otherwise ``ValueError``.
        """
        _check = (
            all((id, dlb, drb)),
            all((dlbf, drbf))
        )
        if not any(_check):
            raise ValueError('Must be specified (id, dlb, drb) or (dlbf, drbf)')

        self.__initialized = False

        if all((dlbf, drbf)):
            if not (dlbf.id == drbf.id):
                raise NotInitializedError('File ID mismatch!')

            if not isinstance(dlbf, DecryptedLocalBoxFile):
                raise TypeError('dlbf must be DecryptedLocalBoxFile')

            if not isinstance(drbf, DecryptedRemoteBoxFile):
                raise TypeError('drbf must be DecryptedRemoteBoxFile')

            self.__id = dlbf.id
            self.dlb = dlbf._lb
            self.drb = drbf._rb

            self.dlbf = dlbf
            self.drbf = drbf
        else:
            if not isinstance(dlb, DecryptedLocalBox):
                raise ValueError('dlb must be DecryptedLocalBox')

            if not isinstance(drb, DecryptedRemoteBox):
                raise ValueError('drb must be DecryptedRemoteBox')

            self.__id = id
            self.dlb = dlb
            self.drb = drb

            self.dlbf = None
            self.drbf = None

        self.cache_preview = cache_preview
        self.erase_encrypted_metadata = erase_encrypted_metadata
        self.lazy = lazy

        # Methods from the DecryptedRemoteBoxFile will be initialized
        # after(/inside) the BoxFile.init() call. Otherwise None.
        self.download = None
        self.sender = None
        self.file = None
        self.message = None
        self.file_size = None
        self.file_file_name = None
        self.box_channel = None
        self.updated_at_time = None

    def __repr__(self) -> str:
        return (
            f'''<{self.__class__.__name__} @ {self.dlbf.file_name} '''
            f'''>> {self.dlbf=}, {self.drbf=}'''
        )
    def __str__(self) -> str:
        return repr(self)

    def __raise_initialized(self) -> NoReturn:
        if not self.__initialized:
            raise NotInitializedError('Not initialized. Call .init().')

    @property
    def initialized(self) -> bool:
        """Returns ``True`` if you called ``.init()``"""
        return self.__initialized

    async def load_drbf(self):
        """Will load and set ``self.drbf`` if it's ``None``"""
        if not self.drbf:
            self.lazy = False
            await self.init()

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

        if not self.__initialized or not all((self.dlbf, self.drbf)):
            elbf = EncryptedLocalBoxFile(
                id=self.__id, elb=self.dlb._elb,
                cache_preview=self.cache_preview)

            await elbf.init()

            super().__init__(elbf=elbf, dlb=self.dlb, cache_preview=self.cache_preview,
                erase_encrypted_metadata=self.erase_encrypted_metadata)

            if self.lazy:
                self.dlbf = await self.dlb.get_file(self.id,
                    cache_preview=self.cache_preview)
            else:
                if not self.drbf and self.dlbf is not None:
                    self.drbf = await self.drb.get_file(self.id,
                        cache_preview=self.cache_preview)
                else:
                    self.dlbf, self.drbf = await gather(
                        self.dlb.get_file(self.id, cache_preview=self.cache_preview),
                        self.drb.get_file(self.id, cache_preview=self.cache_preview)
                    )
                if not all((self.dlbf, self.drbf)):
                    raise InvalidFile('Your Box is out of Sync! Use .sync(deep=True)')

                if not self.dlbf.has_hmac_sha256 == self.drbf.has_hmac_sha256:
                    raise InvalidFile(
                       f'Your Remote File ID{dlbf.id} was changed by third person!!!! '
                        'Review the peoples that have access to editing YOUR files and'
                        'then review changed File! DO NOT TRUST IT! Consider re-upload!'
                    )
        else:
            if not self.dlbf._elbf.initialized:
                await self.dlbf._elbf.init()

            if not self.__initialized:
                super().__init__(elbf=self.dlbf._elbf, dlb=self.dlb,
                    cache_preview=self.cache_preview,
                    erase_encrypted_metadata=self.erase_encrypted_metadata)

        if not self.lazy:
            self.download = self.drbf.download
            self.sender = self.drbf.sender
            self.file = self.drbf.file
            self.message = self.drbf.message
            self.file_size = self.drbf.file_size
            self.file_file_name = self.drbf.file_file_name
            self.box_channel = self.drbf.box_channel
            self.updated_at_time = self.drbf.updated_at_time

        if getattr(self, '_needs_syncify', None):
            syncify(self) # Here we Syncify inherited methods of super()

        self.__initialized = True
        return self

    async def update_metadata(self, *args, **kwargs):
        """
        See ``help(DecryptedLocalBoxFile.update_metadata)``.
        ``drbf`` is auto passed to ``update_metadata()``.
        """
        self.__raise_initialized()

        r = await self.dlbf.update_metadata(
            *args, **kwargs, drbf=self.drbf)

        # self.dlbf & self.drbf will be updated
        # after 'update_metadata()', but 'self'
        # will stay the same, so we need to
        # explicitly update class properties
        self._cattrs = self.dlbf._cattrs
        self._duration = self.dlbf._duration
        self._file_name = self.dlbf._file_name
        self._mime = self.dlbf._mime
        self._preview = self.dlbf._preview
        #
        self._file_path = self.dlbf._file_path
        self._directory = self.dlbf._directory

    async def update(self, *args, **kwargs) -> 'BoxFile':
        """
        See ``help(DecryptedRemoteBox.update_file)``.
        ``rbf`` is auto passed to ``update_file()``.

        ``self`` will be NOT updated! Instead, a new
        ``BoxFile`` object will be returned.
        """
        self.__raise_initialized()

        drbf = await self.drb.update_file(self.drbf, *args, **kwargs)
        dlbf = await self.dlb.get_file(self.drbf.id)
        return await BoxFile(dlbf=dlbf, drbf=drbf).init()

    async def exists(self, *args, **kwargs):
        """
        See ``help(DecryptedRemoteBox.file_exists)``.
        ``id`` is auto passed to ``file_exists()``.
        """
        self.__raise_initialized()
        return await self.drb.file_exists(*args, **kwargs, id=self.dlbf.id)

    async def delete(self, remote: Optional[bool] = False, *args, **kwargs):
        """
        See ``help(DecryptedLocalBoxFile.delete)`` &
        see ``help(DecryptedRemoteBoxFile.delete)``.

        If ``remote`` is ``True``, will be called the same
        method on the ``DecryptedRemoteBoxFile``, deleting
        file in the Local & Remote Box. Do NOT set this
        kwarg to ``True`` if you don't want to completly
        destroy and remove from Box your uploaded file.
        """
        self.__raise_initialized()
        await self.dlbf.delete(*args, **kwargs)
        if remote:
            await self.drbf.delete(*args, **kwargs)

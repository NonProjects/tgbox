try:
    from regex import search as re_search
except ImportError:
    from re import search as re_search

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

from telethon.tl.custom.file import File
from telethon.tl.functions.messages import (
    EditChatAboutRequest
)
from telethon.tl.functions.channels import (
    CreateChannelRequest, EditPhotoRequest,
    GetFullChannelRequest
)
from telethon.tl.types import (
    Channel, Message, PeerChannel
)
from .crypto import (
    aes_decrypt, aes_encrypt, AESwState
)
from .keys import (
    make_filekey, make_requestkey,
    make_sharekey, MainKey, RequestKey, 
    ShareKey, ImportKey, FileKey, BaseKey,
    EncryptedMainkey, make_mainkey
)
from .constants import (
    VERSION, VERBYTE, BOX_IMAGE_PATH, 
    DOWNLOAD_PATH, API_ID, API_HASH, FILESIZE_MAX,
    FILE_NAME_MAX, FOLDERNAME_MAX, COMMENT_MAX,
    PREVIEW_MAX, DURATION_MAX, DEF_NO_FOLDER
)
from .db import TgboxDB

from .errors import (
    IncorrectKey, NotInitializedError,
    InUseException, BrokenDatabase,
    AlreadyImported, RemoteFileNotFound,
    NotImported
)
from sqlite3 import IntegrityError

from .tools import (
    int_to_bytes, bytes_to_int, make_image_preview, 
    make_media_preview, SearchFilter, OpenPretender, 
    make_folder_id, get_media_duration, float_to_bytes, 
    bytes_to_float, prbg, RemoteBoxFileMetadata
)
from typing import (
    BinaryIO, Union, NoReturn, 
    Generator, List, Optional
)
from dataclasses import dataclass
from mimetypes import guess_type
from os.path import getsize
from pathlib import Path

from os import urandom
from io import BytesIO
from time import time

from base64 import (
    urlsafe_b64encode as b64encode, # We use urlsafe base64.
    urlsafe_b64decode as b64decode
)
#__all__ = [] TODO: square previews. Test with PyAes.

TelegramClient.__version__ = VERSION

async def _search_func(
        sf: SearchFilter, 
        ta: Optional['TelegramAccount'] = None,
        mainkey: Optional[MainKey] = None,
        it_messages: Optional[Generator] = None,
        lb: Optional[Union['DecryptedLocalBox', 'EncryptedLocalBox']] = None) -> Generator:
    '''
    Function used to search for files in dlb and rb. It's
    only for internal use, and you shouldn't use it in your
    own projects. `ta` must be specified with `it_messages`.
    
    If file is imported from other `RemoteBox` and was exported
    to your LocalBox, then we can specify box as `lb`. Generator
    will try to get FILEKEY and decrypt `EncryptedRemoteBoxFile`.
    Otherwise imported file will be ignored.
    '''
    in_func = re_search if sf.re else lambda p,s: p in s
    iter_from = it_messages if it_messages else lb.files()
    
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
        
        if sf.exported is not None:
            if file.exported != sf.exported: 
                continue

        for size in sf.min_size:
            if file_size >= size:
                break
        else: 
            if sf.min_size: continue

        for size in sf.max_size:
            if file_size <= size:
                break
        else: 
            if sf.max_size: continue

        for time in sf.time:
            if all((file.upload_time - time > 0, file.upload_time - time <= 86400)):
                break
        else: 
            if sf.time: continue

        for comment in sf.comment:
            if file.comment and in_func(comment, file.comment):
                break
        else: 
            if sf.comment: continue

        for folder in sf.folder:
            if in_func(folder, file.folder):
                break
        else: 
            if sf.folder: continue

        for file_name in sf.file_name:
            if in_func(file_name, file.file_name):
                break
        else: 
            if sf.file_name: continue

        for file_salt in sf.file_salt:
            if in_func(file_salt, rbf.file_salt):
                break
        else:
            if sf.file_salt: continue

        for verbyte in sf.verbyte:
            if verbyte == rbf.verbyte:
                break
        else:
            if sf.verbyte: continue

        yield file

async def make_remote_box(
        ta: 'TelegramAccount', box_salt: bytes, tgbox_db: Optional[TgboxDB] = None, 
        BOX_IMAGE_PATH: str=BOX_IMAGE_PATH) -> 'RemoteBox':
    
    if not tgbox_db:
        tgbox_db = await (await TgboxDB('tgbox_db')).init()

    channel_name = 'tgbox: ' + tgbox_db.name
    channel = (await ta.TelegramClient(
        CreateChannelRequest(channel_name,'',megagroup=False))).chats[0]
    
    BOX_IMAGE_PATH = await ta.TelegramClient.upload_file(BOX_IMAGE_PATH)
    await ta.TelegramClient(EditPhotoRequest(channel, BOX_IMAGE_PATH)) 
    await ta.TelegramClient(EditChatAboutRequest(channel, b64encode(box_salt).decode()))
    
    return RemoteBox(channel, ta)

async def get_remote_box(
        dlb: Optional['DecryptedLocalBox'] = None, 
        ta: Optional['TelegramAccount'] = None,
        entity: Optional[Union[int, str]] = None) -> 'RemoteBox':
    '''
    Returns `RemoteBox` (`Channel`).
    
    Note that `ta` must be already connected 
    with Telegram via `await ta.connect()`.
    
    Must be specified at least `dlb` or
    `ta` with `entity`. `entity` will be used 
    if specified. Can be Channel ID or Username.
    '''
    if ta:
        account = ta
    else:
        account = TelegramAccount(session=dlb._session)
        await account.connect()
    
    entity = entity if entity else PeerChannel(dlb._box_channel_id)
    channel_entity = await account.TelegramClient.get_entity(entity)
    return RemoteBox(channel_entity, account)

async def make_local_box(
        rb: 'RemoteBox', ta: 'TelegramAccount', 
        mainkey: MainKey, tgbox_db: TgboxDB) -> 'DecryptedLocalBox':
    
    if (await tgbox_db.BoxData.count_rows()): 
        raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

    box_salt = await rb.get_box_salt()

    await tgbox_db.BoxData.insert(
        next(aes_encrypt(int_to_bytes(0), mainkey, yield_all=True)),
        next(aes_encrypt(int_to_bytes(rb._box_channel_id), mainkey, yield_all=True)),
        next(aes_encrypt(int_to_bytes(int(time())), mainkey, yield_all=True)),
        box_salt,
        None, # We aren't cloned box, so Mainkey is empty
        next(aes_encrypt(ta.get_session().encode(), mainkey, yield_all=True))
    )
    return await EncryptedLocalBox(tgbox_db).decrypt(mainkey)

async def get_local_box(
        tgbox_db: TgboxDB, key: Optional[Union[MainKey, BaseKey]] = None, 
        ) -> Union['EncryptedLocalBox', 'DecryptedLocalBox']:
    '''
    Returns LocalBox.
    
    key (`MainKey`, `BaseKey`, optional):
        Returns `DecryptedLocalBox` if specified,
        `EncryptedLocalBox` otherwise (default).
        
        You can specify `key` as `BaseKey` if it's
        was cloned from `RemoteBox` and has BOX_DATA/MAINKEY.
        If it's your LocalBox, then use `MainKey`.
    
    tgbox_db (`TgboxDB`, optional):
        Initialized `TgboxDB`. 
    '''
    if key:
        return await EncryptedLocalBox(tgbox_db).decrypt(key)
    else:
        return await EncryptedLocalBox(tgbox_db).init()

class TelegramAccount:
    def __init__(
        self, api_id: int=API_ID, api_hash: str=API_HASH, 
        phone_number: Optional[str] = None, session: Optional[str] = None):
        
        self._api_id, self._api_hash = api_id, api_hash
        self._phone_number = phone_number
        
        self.TelegramClient = TelegramClient(
            StringSession(session), self._api_id, self._api_hash
        )
    async def connect(self) -> None:
        await self.TelegramClient.connect()

    async def send_code_request(self) -> None:
        await self.TelegramClient.send_code_request(self._phone_number)

    async def sign_in(self, password: str=None, code: int=None) -> None: # todo: return True/False
        if not await self.TelegramClient.is_user_authorized():
            try:
                await self.TelegramClient.sign_in(self._phone_number, code)
            except SessionPasswordNeededError:
                await self.TelegramClient.sign_in(password=password)

    async def log_out(self):
        return await self.TelegramClient.log_out()

    async def resend_code(self, phone_number: str, phone_code_hash: str) -> None: #????/ todo
        await self.TelegramClient(ResendCodeRequest(phone_number, phone_code_hash))

    def get_session(self) -> str:
        return self.TelegramClient.session.save()
    
    async def tgboxes(self, yield_with: str='tgbox: ') -> Generator:
        async for d in self.TelegramClient.iter_dialogs():
            if yield_with in d.title and d.is_channel: 
                yield RemoteBox(d, self)

class RemoteBox:
    def __init__(self, box_channel: Channel, ta: TelegramAccount):
        self._ta = ta
        
        self._box_channel = box_channel
        self._box_channel_id = box_channel.id

        self._box_salt = None 
        # We can't use await in __init__, so 
        # you should call get_box_salt for first.
        self._box_name = None
        # Similar to box_salt, call get_box_name.

    def __hash__(self) -> int:
        return hash((self._box_channel_id,22))
        # ^ Without 22 hash of int wil be equal to object's
        
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self._box_channel_id == other.box_channel_id
        ))
    @property
    def box_channel(self) -> Channel:
        return self._box_channel
    
    @property
    def box_channel_id(self) -> Channel:
        return self._box_channel_id
    
    async def get_box_salt(self) -> bytes:
        '''box_salt will be cached after first func call.'''
        if not self._box_salt:
            full_rq = await self._ta.TelegramClient(
                GetFullChannelRequest(channel=self._box_channel)
            )
            self._box_salt = b64decode(full_rq.full_chat.about)
            
        return self._box_salt
    
    async def get_box_name(self):
        if not self._box_name:
            entity = await self._ta.TelegramClient.get_entity(self._box_channel_id)
            self._box_name = entity.title.split(': ')[1]
        return self._box_name

    async def clone(
            self, mainkey: Union[MainKey, ImportKey],
            basekey: BaseKey, box_path: Optional[Union[Path, str]] = None) -> 'DecryptedLocalBox':
        '''
        '''
        box_path = self._box_name if not box_path else box_path
        tgbox_db = await TgboxDB.create(box_path)

        async for erbf in self.files(decrypt=False, return_imported_as_erbf=True):
            last_file_id = erbf.id; break

        if (await tgbox_db.BoxData.count_rows()): 
            raise InUseException(f'TgboxDB "{tgbox_db.name}" in use. Specify new.')

        await tgbox_db.BoxData.insert(
            next(aes_encrypt(int_to_bytes(last_file_id), mainkey, yield_all=True)),
            next(aes_encrypt(int_to_bytes(self._box_channel_id), mainkey, yield_all=True)),
            next(aes_encrypt(int_to_bytes(int(time())), mainkey, yield_all=True)),
            await self.get_box_salt(),
            next(aes_encrypt(mainkey.key, basekey, yield_all=True)),
            next(aes_encrypt(self._ta.get_session().encode(), basekey, yield_all=True))
        )
        dlb = await EncryptedLocalBox(tgbox_db).decrypt(basekey)

        async for drbf in self.files(key=mainkey, decrypt=True, reverse=True):
            await dlb.import_file(drbf, foldername=drbf.foldername)
        
        return dlb
        
    async def search_file(
            self, sf: SearchFilter, mainkey: Optional[MainKey] = None,
            dlb: Optional['DecryptedLocalBox'] = None) ->\
            Generator[Union['EncryptedRemoteBoxFile', 'DecryptedRemoteBoxFile'], None, None]:
        '''
        '''
        it_messages = self._ta.TelegramClient.iter_messages(
            self._box_channel, ids=sf.id if sf.id else None
        )
        sfunc = _search_func(
            sf, mainkey=mainkey, 
            it_messages=it_messages, 
            lb=dlb, ta=self._ta
        )
        async for file in sfunc:
            yield file
            
    async def push_file(self, ff: 'FutureFile') -> 'DecryptedRemoteBoxFile':
        '''
        Uploads `FutureFile` to the `RemoteBox`.
        
        ff (`FutureFile`):
            File to upload. You should recieve
            it via DecryptedLocalBox.
        '''
        state = AESwState(ff.filekey, ff.file_iv)
        oe = OpenPretender(ff.file, state, mode=1)
        oe.concat_metadata(ff.metadata)
            
        ifile = await self._ta.TelegramClient.upload_file(
            oe, file_name=b64encode(ff.file_salt).decode(), 
            part_size_kb=512, file_size=ff.size
        )
        file_message = await self._ta.TelegramClient.send_file(
            self._box_channel, file=ifile, silent=True,
            force_document=True
        )        
        await ff.make_local(file_message.id, 
            int(file_message.date.timestamp())) 
        
        erbf = await EncryptedRemoteBoxFile(
            file_message, self._ta).init()
        return await erbf.decrypt(ff.dlb._mainkey)
    
    async def file_exists(
            self, lbfi: Union['EncryptedLocalBoxFile', 'DecryptedLocalBoxFile']):
        '''
        '''
        if not lbfi.initialized:
            raise NotInitializedError('LocalBoxFile must be initialized')
        else:
            return True if (await self.get_file(lbfi.id, decrypt=False)) else False
                
    async def get_file(
            self, 
            id: int, 
            key: Optional[Union[MainKey, FileKey, ImportKey]] = None,
            dlb: Optional['DecryptedLocalBox'] = None, 
            decrypt: bool=True,
            return_imported_as_erbf: bool=False,
            ignore_errors: bool=True,
            cache_preview: bool=True) -> Union['EncryptedRemoteBoxFile', 'DecryptedRemoteBoxFile', None]:
        '''
        Returns file from the RemoteBox by the given ID.
        ...
        '''     
        file_iter = self.files(
            key, dlb=dlb, decrypt=decrypt, 
            ids=id, cache_preview=cache_preview,
            return_imported_as_erbf=return_imported_as_erbf,
            ignore_errors=ignore_errors
        )
        try:
            return await file_iter.__anext__()
        except StopAsyncIteration: # If there is no file by `id`.
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
            cache_preview: bool=True) -> Generator[
                Union['EncryptedRemoteBoxFile', 
                      'DecryptedRemoteBoxFile'],
                None, None
            ]:
        '''
        Yields every RemoteBoxFile from Remote Box.
        
        The default order is from newest to oldest, but this
        behaviour can be changed with the `reverse` parameter.
        
        key (`MainKey`, `FileKey`, optional):
            Will be used to decrypt `EncryptedRemoteBoxFile`.
        
        dlb (`DecryptedLocalBox`, optional):
            If file in your `RemoteBox` was imported from
            other `RemoteBox` then you can't decrypt it with
            specified mainkey, but if you already imported it
            to your LocalBox, then you can specify dlb and we 
            will use `FILE_KEY` from the Database.
            
            If `decrypt` specified but there is no `key`,
            then we try to use mainkey from this dlb.
            
            This kwarg works in tandem with `ignore_errors` 
            and `return_imported_as_erbf` if dlb doesn't have
            this file (tip: you need to import it with `dlb.import_file`.
        
        ignore_errors (`bool`, optional):
            Ignore all errors related to decryption of the
            files in your `RemoteBox`. If `True`, (by default) 
            only yields files that was successfully decrypted. Can
            be useful if you have files that was imported from other
            `RemoteBox` and you don't want to specify dlb.
        
        return_imported_as_erbf (`bool`, optional):
            If specified, yields files that generator can't 
            decrypt (imported) as `EncryptedRemoteBoxFile`.
        
        limit (`int` | `None`, optional):
            Number of files to be retrieved. Due to limitations with
            the API retrieving more than 3000 messages will take longer
            than half a minute (or even more based on previous calls).
            The limit may also be `None`, which would eventually return
            the whole history.
                
        offset_id (`int`):
            Offset message ID (only remote files *previous* to the given
            ID will be retrieved). Exclusive.
            
        max_id (`int`):
            All the remote box files with a higher (newer) ID 
            or equal to this will be excluded.

        min_id (`int`):
            All the remote box files with a lower (older) ID 
            or equal to this will be excluded.

        add_offset (`int`):
            Additional message offset (all of the specified offsets +
            this offset = older files).

        search (`str`):
            The string to be used as a search query.

        from_user (`str`, `int`):
            Only messages from this entity will be returned.

        wait_time (`int`):
            Wait time (in seconds) between different
            `GetHistoryRequest` (Telethon). Use this parameter to avoid hitting
            the ``FloodWaitError`` as needed. If left to `None`, it will
            default to 1 second only if the limit is higher than 3000.
            If the ``ids`` parameter is used, this time will default
            to 10 seconds only if the amount of IDs is higher than 300.

        ids (`int`, `list`):
            A single integer ID (or several IDs) for the box files that
            should be returned. This parameter takes precedence over
            the rest (which will be ignored if this is set). This can
            for instance be used to get the file with ID 123 from
            a box channel. Note that if the file-message doesn't exist, 
            `None` will appear in its place, so that zipping the list of IDs
            with the files can match one-to-one.
            
        reverse (`bool`, optional):
            If set to `True`, the remote files will be returned in reverse
            order (from oldest to newest, instead of the default newest
            to oldest). This also means that the meaning of `offset_id`
            parameter is reversed, although `offset_id` still be exclusive. 
            `min_id` becomes equivalent to `offset_id` instead of being `max_id` 
            as well since files are returned in ascending order.
        
        decrypt (`bool`, optional):
            Returns `DecryptedRemoteBoxFile` if `True` (default),
            `EncryptedRemoteBoxFile` otherwise.
        '''        
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
                                        '''You don\'t have FileKey for this file. '''
                                        '''Set to True `return_imported_as_erbf`?'''
                                    ) from None
                            else:
                                # We already imported file, so have FileKey
                                rbf = await EncryptedRemoteBoxFile(
                                    m, self._ta, cache_preview=cache_preview
                                ).decrypt(dlb_file._filekey)
                        else: 
                            raise e # Unknown Exception
                yield rbf
    
    async def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        '''
        Returns `RequestKey` for this Box.
        You should use this method if you want
        to decrypt other's `RemoteBox`.
        
        mainkey (`MainKey`, optional):
            To make a `RequestKey` for other's `RemoteBox`
            you should have your own LocalBox. Take key from
            your `DecryptedLocalBoxFile` and specify it here.
        '''
        box_salt = await self.get_box_salt()
        return make_requestkey(mainkey, box_salt=box_salt)

    async def get_sharekey(
            self, mainkey: MainKey, 
            reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this Box.
        You should use this method if you want
        to share your `RemoteBox` with other people.

        _... You broke the spell and wanted something else ..._

        mainkey (`MainKey`, optional):
            `MainKey` assigned to this `RemoteBox`.
        
        reqkey (`RequestKey`, optional):
            User's `RequestKey`. If isn't specified
            returns `ShareKey` of this box without
            encryption, so anyone with this key can
            decrypt **ALL** files in your `RemoteBox`.
        '''
        box_salt = await self.get_box_salt()
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, 
                mainkey=mainkey, 
                box_salt=box_salt
            )
        else:
            return make_sharekey(mainkey=mainkey)

class EncryptedRemoteBoxFile:
    def __init__(
            self, sended_file: Message, 
            ta: TelegramAccount, 
            cache_preview: bool=True):
        
        self._initialized = False
        
        self._message = sended_file
        self._id = sended_file.id
        self._file = sended_file.file
        
        self._ta = ta
        self._cache_preview = cache_preview
        
        self._box_channel_id = sended_file.peer_id.channel_id
        self._file_size = self._file.size

        self._size, self._time = None, int(self._message.date.timestamp())
        self._upload_time = self._time # Syntax sugar for `dlb.import_file`.
        self._file_iv, self._file_salt = None, None
        self._comment, self._foldername = None, None
        self._duration, self._version_byte = None, None

        self._preview, self._box_salt = None, None
        self._prefix, self._navbytes = None, None
        self._file_name = None

        if self._message.fwd_from:
            self._exported = True            
        else:
            self._exported = False
    
    def __hash__(self) -> int:
        return hash((self._id, self._size))
        # ^ Size will be different in Enc or Dec classes. 
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def initialized(self) -> bool:
        return self._initialized

    @property 
    def exported(self) -> bool:
        '''
        Returns `True` if file was exported
        from other RemoteBox. `False` otherwise.
        .'''
        return self._exported
    
    @property
    def preview(self) -> Union[bytes, None]:
        return self._preview

    @property
    def version_byte(self) -> Union[bytes, None]:
        '''Returns version byte.'''
        return self._version_byte
    
    @property
    def box_salt(self) -> Union[bytes, None]:
        return self._box_salt

    @property
    def time(self) -> Union[int, None]:
        return self._time
    
    @property
    def size(self) -> Union[bytes, int, None]:
        '''
        Returns bytes from `EncryptedRemoteBoxFile`
        and int from `DecryptedRemoteBoxFile`.
        '''
        return self._size
    
    @property
    def file_size(self) -> Union[bytes, int, None]:
        '''
        Returns size of the `File` from `Message`
        object. 
        '''
        return self._file_size
    
    @property
    def duration(self) -> Union[bytes, float, None]:
        '''
        Returns bytes from `EncryptedRemoteBoxFile`
        and float from `DecryptedRemoteBoxFile`.
        '''
        return self._duration
    
    @property
    def file_iv(self) -> Union[bytes, None]:
        '''Returns AES CBC IV for this file.'''
        return self._file_iv
    
    @property
    def comment(self) -> Union[bytes, None]:
        '''Returns file comment.'''
        return self._comment
    
    @property
    def foldername(self) -> Union[bytes, None]:
        '''Returns folder name this file belongs to.'''
        return self._foldername
    
    @property
    def prefix(self) -> Union[bytes, None]:
        return self._prefix
    
    @property
    def file_salt(self) -> Union[bytes, None]:
        '''
        Returns file salt. To create decryption key (filekey)
        for this file you need to call `make_filekey(mainkey, file_salt)`.
        '''
        return self._file_salt
    
    @property
    def id(self) -> int:
        '''Returns message id.'''
        return self._id
     
    @property
    def file(self) -> File:
        '''
        Returns `telethon.tl.custom.file.File` object.
        '''
        return self._file
    
    @property
    def file_name(self) -> Union[bytes, None]:
        '''
        Returns remote file name.
        '''
        return self._file_name
    
    @property
    def box_channel_id(self) -> int:
        '''
        Returns ID of the Box Channel.
        '''
        return self._box_channel_id
    
    def __raise_initialized(self) -> None:
        if not self.initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

    def disable_cache_preview(self) -> None:
        '''
        Sets `self._cache_preview` to `False`
        and removes cached preview from memory.
        '''
        self._cache_preview = False
        self._preview = None
    
    def enable_cache_preview(self) -> None:
        '''
        Sets `self._cache_preview` to `True`.
        Preview will be cached after first
        `object.get_preview()` call.
        '''
        self._cache_preview = True
    
    async def init(self) -> 'EncryptedRemoteBoxFile':
        async for fixed_metadata in self._ta.TelegramClient.iter_download(
            self._message.document, offset=0, request_size=103):
                self._prefix = bytes(fixed_metadata[:6])
                self._version_byte = bytes(fixed_metadata[6:7])
                self._box_salt = bytes(fixed_metadata[7:39])
                self._file_salt = bytes(fixed_metadata[39:71])
                self._navbytes = bytes(fixed_metadata[71:])
                break
        self._initialized = True
        return self

    async def delete(self) -> None: 
        '''
        TOTALLY removes file from RemoteBox. You and all
        participants of the `RemoteBox` will
        lose access to it FOREVER. This action can't be
        undone. You need to have rights for this.
        
        Please note that if you want to delete file
        only from your LocalBox then you can use the
        same `delete()` func on your LocalBoxFile.
        '''
        await self._ta.TelegramClient.delete_messages(
            self._box_channel_id, [self._id]
        )
    
    def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        '''
        Returns `RequestKey` for this file. You should
        use this method if you want to decrypt other's
        `EncryptedRemoteBoxFile`.

        mainkey (`MainKey`):
            To make a `RequestKey` of other's RemoteBoxFile
            you need to have your own LocalBox & `RemoteBox`. 
            Take key from your `DecryptedLocalBox` and specify here.
        '''
        self.__raise_initialized()
        return make_requestkey(mainkey, file_salt=self._file_salt)
    
    async def decrypt(
            self, key: Union[MainKey, FileKey, ImportKey, BaseKey])\
            -> 'DecryptedRemoteBoxFile':

        if not self.initialized:
            await self.init()
        return await DecryptedRemoteBoxFile(self, key).init()

class DecryptedRemoteBoxFile(EncryptedRemoteBoxFile):
    def __init__(
            self, erbf: EncryptedRemoteBoxFile, 
            key: Union[MainKey, FileKey, ImportKey]):
        
        if not erbf.initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

        self._key = key
        self._erbf = erbf
        
        self._initialized = False
        self._message = erbf._message
        self._id = erbf._id
        self._file = erbf._file
        
        self._ta = erbf._ta
        self._cache_preview = erbf._cache_preview
        
        self._box_channel_id = erbf._box_channel_id
        self._file_size = erbf._file_size
        
        self._time, self._size = erbf._time, None
        self._upload_time = self._time # Syntax sugar for `dlb.import_file`.
        self._file_iv, self._file_salt = None, erbf._file_salt
        self._comment, self._foldername = None, None
        self._duration, self._version_byte = None, erbf._version_byte

        self._preview, self._exported = None, erbf._exported
        self._prefix, self._navbytes = erbf._prefix, None
        self._box_salt, self._file_name = erbf._box_salt, None
        self._preview_pos, self._file_pos = None, None

        if isinstance(key, (FileKey, ImportKey)):
            self._filekey = FileKey(key.key)
            self.__mainkey = None
        elif isinstance(key, BaseKey):
            self.__mainkey = make_mainkey(key, self._box_salt)
            self._filekey = make_filekey(self.__mainkey, self._file_salt)
        else:
            self.__mainkey = self._key
            self._filekey = make_filekey(self._key, self._file_salt)
            
    def __raise_initialized(self) -> None:
        if not self._initialized:
            raise NotInitializedError('RemoteBoxFile must be initialized.')

    async def init(self) -> 'DecryptedRemoteBoxFile':
        dec_navbytes = next(aes_decrypt(
            self._erbf._navbytes, self._filekey, yield_all=True)
        )
        filedata_len = bytes_to_int(dec_navbytes[:3],signed=False)
        preview_len = bytes_to_int(dec_navbytes[3:],signed=False)
        #TODO: BIG FILEDATA LEN IS BROKEN

        async for filedata in self._ta.TelegramClient.iter_download(
            self._message.document, offset=103, request_size=filedata_len):
                # filedata = filedata[103:] # TODO: assigned to Broken fdata len.
                # ^ Offset need to be removed if fixed req_size

                dec_filedata = next(aes_decrypt(
                    filedata, self._filekey, yield_all=True)
                )
                self._size = bytes_to_int(dec_filedata[:4],signed=False)
                self._duration = bytes_to_int(dec_filedata[4:8],signed=False)
                folder_len = bytes_to_int(dec_filedata[8:10],signed=False)
                
                self._foldername = dec_filedata[10:10+folder_len] 

                if self.__mainkey:
                    self._foldername = next(aes_decrypt(
                        self._foldername, self.__mainkey, yield_all=True)
                    )
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
        else:
            self._preview = b''
        
        return self

    async def get_preview(self) -> bytes:
        self.__raise_initialized()
        if isinstance(self._preview_pos, tuple) and not self._preview_pos:
            preview = b''
        else:
            async for preview in self._ta.TelegramClient.iter_download(
                self._message.document, offset=self._preview_pos[0], 
                    request_size=self._preview_pos[1]):
                        preview = next(aes_decrypt(
                            preview, self._filekey, yield_all=True)
                        )
                        break
        if self._cache_preview:
            self._preview = preview
        return preview

    async def download( 
            self, *, outfile: Union[str, BinaryIO, Path] = DOWNLOAD_PATH, 
            hide_folder: bool=False, hide_name: bool=False,
            decrypt: bool=True, offset: int=0,  
            request_size: int=524288) -> BinaryIO:
        '''
        Downloads and saves remote box file to the `outfile`.
        
        oufile (`str`, `BinaryIO`, `Path`, optional):
            Path or File-like object to which file will be downloaded.
            `.constants.DOWNLOAD_PATH` by default.
            
            If `outfile` has `.write()` method then we will use it.
        
        hide_folder (`bool`, optional):
            Saves to folder which this file belongs to if False,
            (default) otherwise to `outfile/{constants.DEF_UNK_FOLDER}`.
            
            Doesn't create any folders if `isinstance(outfile, BinaryIO)`.
        
        hide_name (`bool`, optional):
            Saves file with encrypted name if True, with
            decrypted if False (default).
            
            Doesn't create any folders if `isinstance(outfile, BinaryIO)`.
        
        decrypt (`bool`, optional):
            Decrypts file if True (default).
        
        request_size (`int`, optional):
            How many bytes will be requested to Telegram when more 
            data is required. By default, as many bytes as possible 
            are requested. If you would like to request 
            data in smaller sizes, adjust this parameter.

            Note that values outside the valid range will be clamped, 
            and the final value will also be a multiple of the minimum allowed size.
        
        offset (`int`, optional):
            The offset in bytes into the file from where the 
            download should start. For example, if a file is 
            1024KB long and you just want the last 512KB, 
            you would use `offset=512 * 1024`.
        '''
        self.__raise_initialized()
        
        if decrypt:
            aws = AESwState(self._filekey, self._file_iv)
        
        if isinstance(outfile, (str, Path)):
            Path('BoxDownloads').mkdir(exist_ok=True)
            outfile = Path(outfile) if not isinstance(outfile, Path) else outfile

            folder = DEF_UNK_FOLDER if hide_folder else self._foldername
            folder = DEF_NO_FOLDER if not folder else folder
            name = prbg(16).hex() if hide_name else self._file_name
            
            outfile = Path(outfile, folder.decode())
            outfile.mkdir(exist_ok=True, parents=True)

            outfile = open(Path(outfile, name.decode()),'wb')
            
        elif isinstance(outfile, BinaryIO) or hasattr(outfile, 'write'):
            pass # We already can write 
        else:
            raise TypeError('outfile not Union[BinaryIO, str].')
        
        if offset and decrypt:
            raise ValueError('Can\'t decrypt with `offset`')
        elif not offset:
            offset = self._file_pos
        
        iter_down = self._ta.TelegramClient.iter_download(
            self._message.document, offset=offset, 
            request_size=request_size
        )
        downloaded = 0
        async for chunk in iter_down: 
            downloaded += len(chunk)
            if downloaded >= self.size:
                outfile.write(aws.decrypt(chunk, unpad=True) if decrypt else chunk)
            else:
                outfile.write(aws.decrypt(chunk) if decrypt else chunk)

        return outfile
    
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this file. You should
        use this method if you want to share this
        file with other people.
        
        reqkey (`RequestKey`, optional):
            Other's `RequestKey`. If isn't specified
            returns `ImportKey` of this file without
            encryption, so **ANYONE** with this key 
            can decrypt this remote file.
        '''
        self.__raise_initialized()

        if reqkey:
            return make_sharekey(
                requestkey=reqkey, filekey=self._filekey, 
                file_salt=self._file_salt
            )
        else:
            return make_sharekey(filekey=self._filekey)
        
class EncryptedLocalBox: 
    def __init__(self, tgbox_db: TgboxDB):
        self._tgbox_db = tgbox_db
        
        self._mainkey = None
        self._box_salt = None
        self._session = None
        self._box_channel_id = None
        self._box_cr_time = None
        self._last_file_id = None

        self._initialized = False
        self._enc_class = True
            
    def __hash__(self) -> int:
        return hash((self._box_salt, self._session))
        # ^ Session will be different in Enc or Dec classes.
        
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().')

    @property     
    def tgbox_db(self) -> TgboxDB:
        return self._tgbox_db
   
    @property
    def is_enc_class(self) -> bool:
        return self._enc_class

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property 
    def box_salt(self) -> Union[bytes, None]:
        return self._box_salt
    
    @property
    def session(self) -> Union[bytes, str, None]:
        return self._session
    
    @property
    def box_channel_id(self) -> Union[bytes, str, None]:
        return self._box_channel_id
    
    @property
    def box_cr_time(self) -> Union[bytes, str, None]:
        return self._box_cr_time
    
    @property
    def last_file_id(self) -> Union[bytes, str, None]:
        return self._last_file_id
    
    async def init(self) -> 'EncryptedLocalBox':
        if not await self._tgbox_db.BoxData.count_rows():
            raise NotInitializedError('Table is empty.') 
        else:
            box_data = await self._tgbox_db.BoxData.select_once()
            self._last_file_id, self._box_channel_id = box_data[:2]
            self._box_cr_time, self._box_salt, self._mainkey = box_data[2:5]
            self._session, self._initialized = box_data[5], True
            
            if self._mainkey:
                self._mainkey = EncryptedMainkey(self._mainkey)

        return self

    async def get_file(self, id: int, cache_preview: bool=True)\
            -> Union['DecryptedLocalBoxFile', 'EncryptedLocalBoxFile', None]:
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
        except StopAsyncIteration: # No file by `id`.
            return None
    
    async def files(self, cache_preview: bool=True)\
            -> Union['DecryptedLocalBoxFile', 'EncryptedLocalBoxFile', None]:

        cursor = await self._tgbox_db.Files.execute(('SELECT ID FROM FILES',()))
        async for file_id in cursor:
            yield await self.get_file(file_id[0], cache_preview=cache_preview)

    def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        '''
        Returns `RequestKey` for this LocalBox. You
        should use this method if you want to decrypt
        other's `EncryptedLocalBox`.

        mainkey (`MainKey`):
            To make a `RequestKey` for other's
            `EncryptedLocalBox` you need to have
            your own. Take key from it and specify here.
        '''
        self.__raise_initialized()
        return make_requestkey(mainkey, box_salt=self._box_salt)

    async def decrypt(self, key: Union[MainKey, ImportKey, BaseKey]) -> 'DecryptedLocalBox':
        if not self.initialized:
            await self.init()
        return DecryptedLocalBox(self, key)

class DecryptedLocalBox(EncryptedLocalBox):
    def __init__(
            self, elb: EncryptedLocalBox, 
            key: Union[MainKey, ImportKey, BaseKey]):
        
        if not elb.initialized:
            raise NotInitializedError('Parent class isn\'t initialized.')

        self._elb = elb
        self._tgbox_db = elb._tgbox_db
        self._initialized = True 
        self._enc_class = False
        
        if isinstance(key, (MainKey, ImportKey)):
            self._mainkey = MainKey(key.key)
            
        elif isinstance(key, BaseKey):
            if isinstance(elb._mainkey, EncryptedMainkey):
                mainkey = next(aes_decrypt(elb._mainkey.key, key, yield_all=True))
                self._mainkey = MainKey(mainkey)
            else:
                self._mainkey = make_mainkey(key, self._elb._box_salt)
                key = self._mainkey
        
        else:
            raise IncorrectKey('key is not Union[MainKey, ImportKey, BaseKey]')
        
        try:
            # When we clone other's RemoteBox, we encrypt Session with Basekey,
            # to prevent stealing Session information by people who also have
            # mainkey of the same box. So there is decryption with `key`.
            self._session = next(aes_decrypt(
                elb._session, key, yield_all=True)).decode()
        except UnicodeDecodeError:
            raise IncorrectKey('Can\'t decrypt Session. Invalid Phrase/Basekey?') from None

        self._box_channel_id = bytes_to_int(next(
            aes_decrypt(elb._box_channel_id, self._mainkey, yield_all=True))
        )
        self._box_cr_time = bytes_to_int(next(
            aes_decrypt(elb._box_cr_time, self._mainkey, yield_all=True))
        )
        if elb._last_file_id:
            self._last_file_id = bytes_to_int(next(
                aes_decrypt(elb._last_file_id, self._mainkey, yield_all=True))
            )
        self._box_salt = elb._box_salt 

    @staticmethod
    def init() -> NoReturn:
        raise AttributeError(
            '''This function was inherited from `EncryptedLocalBox` '''
            '''and cannot be used on `DecryptedLocalBox`.'''
        )
    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            '''This function was inherited from `EncryptedLocalBox` '''
            '''and cannot be used on `DecryptedLocalBox`.'''
        )
    async def folders(self) -> 'LocalBoxFolder': 
            folders_list = await self._tgbox_db.Folders.execute(
                (f'SELECT * FROM FOLDERS',)
            )
            async for folder in folders_list:
                yield LocalBoxFolder(
                    self._tgbox_db, self._mainkey,
                    enc_foldername=folder[0],
                    foldername_iv=folder[1],
                    folder_id=folder[2]
                )

    async def search_file(self, sf: SearchFilter, mainkey: Optional[MainKey] = None):
        mainkey = mainkey if (not hasattr(self, '_mainkey') and not mainkey) else self._mainkey
        async for file in _search_func(sf, lb=self, mainkey=mainkey):
            yield file
        
    async def make_file( 
            self, file: Union[BinaryIO, BytesIO, bytes],
            file_size: Optional[int] = None,
            foldername: bytes=DEF_NO_FOLDER, 
            comment: bytes=b'',
            make_preview: bool=True) -> 'FutureFile':
        '''
        file (`BinaryIO`, `BytesIO`):
            `file` data to add to the LocalBox. In most
            cases it's just opened file. If you want to upload
            something else, then you need to implement class
            that have `read` & `name` methods.
            
            The method needs to know size of the `file`, so
            it will try to ask system what size of file on path
            `file.name`. If it's impossible, then method tries to
            seek file to EOF, if file isn't seekable, then we try to
            get size by `len()` (as `__len__` dunder). If all fails,
            method tries to get file.read())` (with load to RAM).
            
            File name length must be <= `constants.FILE_NAME_MAX`;
            Filesize must be <= `constants.FILESIZE_MAX`;
            If file has no `name` then it will be `prbg(6).hex()`.
        
        file_size (`int`, optional):
            Bytelength of `file`. You can specify
            it if you already know file size.

        foldername (`bytes`, optional):
            Folder to add this file to.
            Must be <= `constants.FOLDERNAME_MAX`.
        
        comment (`bytes`, optional):
            File comment. Must be <= `constants.COMMENT_MAX`.
        
        make_preview (`bool`, optional):
            Will try to add file preview to 
            the Metadata if `True` (default).
        '''
        if len(comment) > COMMENT_MAX:
            raise ValueError(f'Comment length must be <= {COMMENT_MAX} bytes.')
                
        file_salt, file_iv = urandom(32), urandom(16)
        filekey = make_filekey(self._mainkey, file_salt)
        
        if hasattr(file, 'name'):
            file_path = Path(file.name)
            file_name = file_path.name
            if len(file_name) > FILE_NAME_MAX: 
                raise ValueError(f'File name must be <= {FILE_NAME_MAX} symbols.')
        else:
            file_name, file_path = prbg(8).hex(), ''
        
        if not file_size:
            try:
                file_size = getsize(file.name)
            except FileNotFoundError:
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
                    
            if file_size <= 0:
                raise ValueError('File can\'t be empty.')
            elif file_size > FILESIZE_MAX:
                raise Exception(f'File size limit is {FILESIZE_MAX} bytes.')
        
        gtype = guess_type(file_name)

        if gtype[0]:
            type_ = gtype[0].split('/')[0]

            if type_ in ('audio','video'):
                preview_func = make_media_preview
            elif type_ == 'image':
                preview_func = make_image_preview
            else:
                preview_func = None

            if make_preview and preview_func:
                try:
                    preview = await preview_func(file.name)
                except PreviewImpossible:
                    preview = b''
            else:
                preview = b''

            if preview_func == make_media_preview:
                try:
                    duration = await get_media_duration(file.name) 
                except:
                    duration = 0
            else:
                duration = 0
        else:
            preview, duration = b'', 0
        
        preview = b'' if len(preview) > PREVIEW_MAX else preview
        # ^ Although we store preview size in 3 bytes, the max
        # ^ preview size is 1MB-16b (PREVIEW_MAX), not 16MiB.
        duration = 0 if duration > DURATION_MAX else duration
        # ^ Duration can't be bigger than DURATION_MAX. As per
        # ^ v1.0 it's ~68.1 years. More than enough.
        return FutureFile(
            dlb=self, 
            file_name=file_name,
            foldername=foldername, 
            file=file,
            filekey=filekey, 
            comment=comment,
            size=file_size, 
            preview=preview, 
            duration=duration,
            file_salt=file_salt, 
            file_iv=file_iv, 
            verbyte=VERBYTE,
            imported=False
        )
    async def import_file( 
            self, drbf: DecryptedRemoteBoxFile,
            foldername: Optional[bytes] = None)\
            -> 'DecryptedLocalBoxFile':

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
    
    async def download_file(
            self, rb: RemoteBox, 
            dlbfi: 'DecryptedLocalBoxFile', 
            **kwargs) -> BinaryIO:
        '''
        Downloads file from `RemoteBox` similiar to the
        `DecryptedRemoteBoxFile.download(**kwargs)`. It's
        like syntactic sugar to make your life easier.
        '''
        key = dlbfi._filekey if dlbfi.exported else dlbfi._key
        
        return await (await rb.get_file(
            dlbfi.id, key, decrypt=True)
        ).download(**kwargs)
    
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this Box. You should use
        this method if you want to share your LocalBox
        with other people.
        
        reqkey (`RequestKey`, optional):
            Other's `RequestKey`. If isn't specified
            returns `ImportKey` of this box without
            encryption, so anyone with this key can
            decrypt **ALL** files in your Boxes.
        '''
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, 
                mainkey=self._mainkey, 
                file_salt=self._box_salt
            )
        else:
            return make_sharekey(mainkey=self._mainkey)
    
class LocalBoxFolder:
    def __init__(
            self, tgbox_db: TgboxDB, 
            mainkey: MainKey, 
            enc_foldername: bytes,
            foldername_iv: bytes,
            folder_id: bytes):

        self._tgbox_db = tgbox_db
        
        self._enc_foldername = enc_foldername
        self._foldername_iv = foldername_iv
        self._folder_id = folder_id

        self._dec_foldername = next(aes_decrypt(
            self._enc_foldername, mainkey, 
            iv=self._foldername_iv, yield_all=True
        ))
        self.__mainkey = mainkey

    def __hash__(self) -> int:
        return hash((self._enc_foldername, 22))
        # ^ Without 22 hash of str wil be equal to object's
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def enc_foldername(self) -> bytes:
        return self._enc_foldername
    
    @property
    def dec_foldername(self) -> bytes:
        return self._dec_foldername

    async def files(self, cache_preview: bool=True) -> 'DecryptedLocalBoxFile':
        files_list = await self._tgbox_db.Files.execute( 
            ('SELECT * FROM FILES WHERE FOLDER_ID = ?', (self._folder_id,))
        )
        async for file_row in files_list:
            yield await self.get_file(file_row[0], cache_preview=cache_preview)

    async def get_file(
            self, id: int, cache_preview: bool=True
            ) -> 'DecryptedLocalBoxFile':
        '''
        Returns file by given ID.
        
        id (`int`):
            ID of the uploaded to `RemoteBox` file.

        cache_preview (optional, `bool`):
            Will save preview image (max 1MB) in 
            `EncryptedLocalBoxFile` object if `True` (default).
        '''
        return await EncryptedLocalBoxFile(
            id, self._tgbox_db, cache_preview=cache_preview
        ).decrypt(self.__mainkey)

    async def delete(self) -> None: 
        '''
        Will delete this folder with all files from your LocalBox.
        All files will stay in `RemoteBox`, so you can restore
        all your folders by importing files.
        '''
        await self._tgbox_db.Files.execute(
            ('DELETE FROM FILES WHERE FOLDER_ID=?',(self._folder_id,))
        )
        await self._tgbox_db.Folders.execute(
            ('DELETE FROM FOLDERS WHERE FOLDER_ID=?',(self._folder_id,))
        )

class EncryptedLocalBoxFile:   
    def __init__(
            self, id: int, tgbox_db: TgboxDB, 
            cache_preview: bool=True) -> None:
        
        self._tgbox_db = tgbox_db
        self._cache_preview = cache_preview
        
        self._enc_class = True
        self._initialized = False
        
        self._foldername, self._preview = None, None
        self._foldername_iv, self._folder = None, None
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
        return self._enc_class
   
    @property
    def initialized(self) -> bool:
        return self._initialized
    
    @property
    def file(self) -> Union[BinaryIO, None]:
        '''
        Returns opened file as `BinaryIO` if it was 
        downloaded, otherwise `None`. File returns 
        "as is", and it will be not decrypted if 
        you downloaded it in encrypted state.
        
        Will always return `None` from 
        `EncryptedLocalBoxFile`, because `FILE_PATH`
        is encrypted with filekey.
        '''
        return self._file
    
    @property
    def exported(self) -> Union[bool, None]:
        return self._exported
    
    @property
    def version_byte(self) -> Union[bytes, None]:
        return self._version_byte
    
    @property
    def file_path(self) -> Union[str, None]:
        return self._file_path

    @property
    def file_name(self) -> Union[str, None]:
        return self._file_name

    @property
    def foldername(self) -> Union[str, None]:
        return self._foldername

    @property
    def size(self) -> Union[bytes, int, None]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and int from `DecryptedLocalBoxFile`.
        '''
        return self._size
    
    @property
    def duration(self) -> Union[bytes, float, None]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and float from `DecryptedLocalBoxFile`.
        '''
        return self._duration
    
    @property
    def comment(self) -> Union[bytes, None]:
        '''Returns file comment.'''
        return self._comment

    @property
    def id(self) -> Union[bytes, int, None]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and int from `DecryptedLocalBoxFile`.
        '''
        return self._id
    
    @property
    def file_iv(self) -> Union[bytes, None]:
        '''
        Returns encrypted FILE_IV from `EncryptedLocalBoxFile`
        and decrypted FILE_IV from `DecryptedLocalBoxFile`.
        '''
        return self._file_iv

    @property
    def upload_time(self) -> Union[bytes, int, None]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and int from `DecryptedLocalBoxFile`.
        '''
        return self._upload_time

    @property
    def file_salt(self) -> Union[bytes, None]:
        '''
        Returns `FILE_SALT`.
        
        You can get decryption key for this file
        with `.crypto.make_filekey(mainkey, file_salt)`.
        '''
        return self._file_salt

    @property
    def preview(self) -> Union[bytes, None]:
        '''
        Returns file preview. If there is no
        preview then returns `b''`.
        ''' 
        return self._preview
    
    def __raise_initialized(self) -> NoReturn:
        if not self._initialized:
            raise NotInitializedError('Not initialized. Call .init().') 
    
    async def init(self) -> 'EncryptedLocalBoxFile':
        sql_file_row = await self._tgbox_db.Files.select_once(
            sql_tuple = ('SELECT * FROM FILES WHERE ID = ?', (self._id,))
        )
        self._file_name, self._folder_id = sql_file_row[6], sql_file_row[1]
        
        self._comment, self._size = sql_file_row[2], sql_file_row[9]
        self._duration, self._id = sql_file_row[3], sql_file_row[0]
        self._upload_time, self._file_salt = sql_file_row[10], sql_file_row[7] 
        self._file_iv, self._filekey = sql_file_row[4], sql_file_row[5]
        self._version_byte, self._file_path = sql_file_row[11], sql_file_row[12]
        
        if self._cache_preview:
            self._preview = sql_file_row[8]
        else:
            self._preview = None
        
        try:
            cursor = await self._tgbox_db.Folders.execute(
                ('SELECT * FROM FOLDERS WHERE FOLDER_ID = ?',(self._folder_id,))
            )
            self._foldername, self._foldername_iv, self._folder_id = (
                await cursor.fetchone()
            )
        except Exception as e:
            raise BrokenDatabase(f'Can\'t read your DB. {e}') from None

        self._exported = True if self._filekey else False
        self._initialized = True

        return self

    def disable_cache_preview(self) -> None:
        '''
        Sets `self._cache_preview` to `False`
        and removes cached preview from memory.
        '''
        self._cache_preview = False
        self._preview = None
    
    def enable_cache_preview(self) -> None:
        '''
        Sets `self._cache_preview` to `True`.
        Preview will be cached after first
        `object.preview` call.
        '''
        self._cache_preview = True
    
    def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        ''' 
        Returns `RequestKey` for this File. You
        should use this method if you want to decrypt
        other's `EncryptedLocalBoxFile`.

        mainkey (`MainKey`):
            To make a `RequestKey` for other's
            `EncryptedLocalBoxFile` you need to have
            your own Box. Take key from it and specify here.
        '''
        self.__raise_initialized()
        return make_requestkey(mainkey, file_salt=self._file_salt)

    async def decrypt(self, key: Union[FileKey, MainKey]) -> 'DecryptedLocalBoxFile':
        if not self.initialized:
            await self.init()
        return DecryptedLocalBoxFile(self, key)

    async def delete(self) -> None:
        '''
        Will delete this file from your LocalBox.
        You can re-import it from `RemoteBox` with
        `import_file`. To remove your file totally
        please use same function on RemoteBoxFile.
        '''
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
    def __init__(
            self, elbfi: EncryptedLocalBoxFile, 
            key: Union[FileKey, ImportKey, MainKey],
            cache_preview: Optional[bool] = None):
        
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
            self._filekey = FileKey(next(aes_decrypt(
                self._filekey, self._key, yield_all=True)))
        else:
            self._filekey = make_filekey(self._key, self._file_salt)
        
        if isinstance(key, MainKey):
            self.__mainkey = key
        else:
            self.__mainkey = None

        self._preview, self._folder = elbfi._preview, None
        self._foldername_iv = elbfi._foldername_iv
        self._file_iv, self._folder_id = elbfi._file_iv, elbfi._folder_id
        self._id, self._file_salt = elbfi._id, elbfi._file_salt
        self._version_byte = elbfi._version_byte
        self._exported = True if elbfi._filekey else False

        if elbfi._file_path: 
            self._file_path = next(aes_decrypt(
                elbfi._file_path, self._filekey, yield_all=True)
            ).decode()
            self._file = open(self._file_path,'rb')
        else:
            self._file_path, self._file = None, None

        self._file_name = next(aes_decrypt(
            elbfi._file_name, self._filekey, yield_all=True)
        )
        if self.__mainkey:
            self._foldername = next(aes_decrypt(
                elbfi._foldername, self.__mainkey, 
                iv=self._foldername_iv, yield_all=True)
            )
        else:
            self._foldername = DEF_NO_FOLDER

        self._comment = next(aes_decrypt(
            elbfi._comment, self._filekey, yield_all=True)
        )
        self._size = bytes_to_int(next(aes_decrypt(
            elbfi._size, self._filekey, yield_all=True)
        ))
        self._duration = bytes_to_float(next(aes_decrypt(
            elbfi._duration, self._filekey, yield_all=True)
        ))
        self._upload_time = bytes_to_int(next(aes_decrypt( 
            elbfi._upload_time, self._filekey, yield_all=True)
        )) 
        if not self._cache_preview:
            self._preview = None
        
        if self._file_path:
            self._file = open(self._file_path,'rb')
        else:
            self._file = None
        
        if self._preview and self._cache_preview:
            self._preview = next(aes_decrypt(
                elbfi._preview, self._filekey, yield_all=True))
        else:
            self._preview = None
        
        self._download_path = DOWNLOAD_PATH 
    
    @staticmethod
    def init() -> NoReturn:
        raise AttributeError(
            '''This function was inherited from `EncryptedLocalBoxFile` '''
            '''and cannot be used on `DecryptedLocalBoxFile`.'''
        )
    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            '''This function was inherited from `EncryptedLocalBoxFile` '''
            '''and cannot be used on `DecryptedLocalBoxFile`.'''
        )
    @property
    def download_path(self) -> str:
        return self._download_path

    async def get_preview(self) -> bytes: 
        '''
        Returns file preview. If there is no preview 
        then returns `b''`. If `EncryptedLocalBoxFile`
        parent (`self._elbfi`) disabled `cache_preview`, then
        every call of this method will open DB & decrypt PREVIEW.
        '''
        if self._preview:
            return self._preview
        else:
            cursor = await self._tgbox_db.Files.execute(
                ('SELECT PREVIEW FROM FILES WHERE ID=?',(self._id,))
            )
            preview = (await cursor.fetchone())[0]
            preview = next(aes_decrypt(
                preview, self._filekey, yield_all=True)
            )
            if self._cache_preview:
                self._preview = preview
            return preview

    async def get_folder(self, mainkey: Optional[MainKey] = None) -> LocalBoxFolder:
        if not self.__mainkey and not mainkey:
            raise IncorrectKey('You need to specify MainKey')

        if not self._folder:
            self._folder = LocalBoxFolder(
                self._tgbox_db, 
                self.__mainkey, 
                self._elbfi.foldername,
                self._foldername_iv,
                self._folder_id
            )
        return self._folder

    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this file. You should
        use this method if you want to share your
        `DecryptedLocalBoxFile` with other people.
        
        reqkey (`RequestKey`, optional):
            Other's `RequestKey`. If isn't specified
            returns `ShareKey` of this file without
            encryption, so anyone with this key can
            decrypt this local & remote box file.
        '''
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, filekey=self._filekey, 
                file_salt=self._file_salt
            )
        else:
            return make_sharekey(filekey=self._filekey)

@dataclass
class FutureFile:
    dlb: DecryptedLocalBox
    file_name: str
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
    def metadata(self) -> RemoteBoxFileMetadata:
        if not hasattr(self, '_metadata'):
            enc_foldername = next(aes_encrypt(
                self.foldername, self.dlb._mainkey,
                yield_all=True)
            )
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
        duration = float_to_bytes(self.duration)
        size = int_to_bytes(self.size)
        upload_time = int_to_bytes(upload_time)
        
        # Verify that there is no file with same ID
        try:
            maybe_file = await self.dlb._tgbox_db.Files.select_once(
                sql_tuple=('SELECT ID FROM FILES WHERE ID=?', (id,))
            )
        except StopAsyncIteration:
            pass
        else:
            raise AlreadyImported('There is already file with same ID') from None

        if self.imported:
            filekey = next(aes_encrypt(
                self.filekey.key, 
                self.dlb._mainkey, 
                yield_all=True)
            )
        else:
            filekey = None

        if isinstance(self.file_name, bytes):
            file_name = self.file_name
        else:
            file_name = self.file_name.encode()

        if hasattr(self.file, 'name'):
            file_path = next(aes_encrypt(
                self.file.name.encode(), 
                self.filekey, yield_all=True))
        else:
            file_path = None
        
        folder_id = make_folder_id(self.dlb._mainkey, self.foldername)

        # We're checking if there is already the same folder (1)
        cursor = await self.dlb._tgbox_db.Folders.execute(
            ('SELECT FOLDER_ID FROM FOLDERS WHERE FOLDER_ID = ?', (folder_id,))
        )
        # And if not, we're add it (2)
        if not await cursor.fetchone(): 
            folder = next(aes_encrypt(
                self.foldername, 
                self.dlb._mainkey, # We're use MainKey for folder encryption 
                yield_all=True)
            )
            await self.dlb._tgbox_db.Folders.insert(
                folder[16:], folder[:16], folder_id)
        
        await self.dlb._tgbox_db.Files.insert(
            id, 
            folder_id,            
            next(aes_encrypt(self.comment, self.filekey, yield_all=True)),
            next(aes_encrypt(duration, self.filekey, yield_all=True)),
            self.file_iv, 
            filekey,
            next(aes_encrypt(file_name, self.filekey, yield_all=True)),
            self.file_salt,
            next(aes_encrypt(self.preview, self.filekey, yield_all=True)),
            next(aes_encrypt(size, self.filekey, yield_all=True)),
            next(aes_encrypt(upload_time, self.filekey, yield_all=True)),
            self.verbyte,
            file_path
        )
        enc_id = next(aes_encrypt(
            int_to_bytes(id), 
            self.dlb._mainkey, 
            yield_all=True)
        )
        sql_tuple = ('UPDATE BOX_DATA SET LAST_FILE_ID = ?',(enc_id,))
        await self.dlb._tgbox_db.BoxData.execute(sql_tuple) 

        return await EncryptedLocalBoxFile(
            id, self.dlb._tgbox_db).decrypt(self.filekey)

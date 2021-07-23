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
    Channel, InputFile, InputFileBig, 
    Message, PeerChannel
)
from .crypto import (
    aes_decrypt, aes_encrypt, AESwState,
    encrypt_preview, decrypt_preview
)
from .keys import (
    make_filekey, make_requestkey, make_importkey,
    make_sharekey, MainKey, RequestKey, 
    ShareKey, ImportKey, FileKey, BaseKey
)
from .constants import (
    VERSION, VERSION_BYTE, DB_PATH,
    BOX_IMAGE_PATH, DOWNLOAD_PATH, API_ID, API_HASH
)
from .db import (
    init_db, make_db, make_db_folder, 
    make_db_file_folder, get_session,
    rm_db_folder, rm_db_file_folder
)
from .tools import (
    int_to_bytes, bytes_to_int, make_image_preview, 
    make_media_preview, dump_to_datastring, SearchFilter,
    restore_datastring, OpenPretender, make_folder_iv,
    get_media_duration, float_to_bytes, bytes_to_float,
)
from os.path import (
    getsize, join as path_join, sep as path_sep,
    exists as path_exists
)
from typing import (
    BinaryIO, Union, NoReturn, 
    Generator, List, Optional
)
from os import listdir, mkdir, makedirs, urandom
from mimetypes import guess_type
from io import BytesIO

from base64 import (
    urlsafe_b64encode as b64encode, # We use urlsafe base64.
    urlsafe_b64decode as b64decode
)
#__all__ = [] TODO: square previews.

TelegramClient.__version__ = VERSION

async def _search_func(
        sf: SearchFilter, ta: Optional['TelegramAccount'] = None,
        mainkey: Optional[MainKey] = None,
        it_messages: Optional[Generator] = None,
        lb: Optional[Union['DecryptedLocalBox', 'EncryptedLocalBox']] = None) -> Generator:
    '''
    Function used to search for files in dlb and rb. It's
    only for internal use, and you shouldn't use it in your
    own projects. `ta` must be specified with `it_messages`.
    
    If file is imported from other `RemoteBox` and was exported
    to your LocalBox, then we can specify it as `lb`. Generator
    will try to get FILEKEY and decrypt `EncryptedRemoteBoxFile`.
    Otherwise imported file will be ignored.
    '''
    lb_files, lb_folders = None, None
    
    while True:
        if it_messages:
            try:
                message = await it_messages.__anext__()
            except StopAsyncIteration:
                return
                
            if message.document:
                try:
                    bf = EncryptedRemoteBoxFile(message, ta) # bf is BoxFile
                    if mainkey: 
                        pass
                    elif hasattr(lb, '_mainkey'): 
                        mainkey = lb._mainkey
                    bf = bf if not mainkey else bf.decrypt(mainkey)
                except IndexError:
                    continue # Not a tgbox file.
                except ValueError: # Incorrect padding. Imported file.
                    if lb and isinstance(lb, DecryptedLocalBox):
                        dlbfi = lb.get_file(bf.id, decrypt=True)
                        if not dlbfi: 
                            continue
                        else:
                            bf = bf.decrypt(dlbfi._filekey)
                    else:
                        continue
            else:
                continue
        
        elif lb:
            lb_folders = lb_folders if lb_folders else lb.folders() 
            for folder in lb_folders:
                if sf.folder and folder.foldername not in sf.folder:
                    continue
                else:
                    lb_files = lb_files if lb_files else folder.files() 
                    for file in lb_files:
                        bf = file; break
                    else:
                        break
                break
            else:
                return
        else:
            raise ValueError('At least it_messages or dlb must be specified.')
        
        if isinstance(bf, (EncryptedRemoteBoxFile, DecryptedRemoteBoxFile)):
            file_size = bf.file_size
        else:
            file_size = bf.size
        
        if sf.exported is not None:
            if bf.exported != sf.exported: 
                continue

        if sf.min_size:
            for size in sf.min_size:
                if file_size >= size:
                    break
            else: 
                continue

        if sf.max_size:
            for size in sf.max_size:
                if file_size <= size:
                    break
            else: 
                continue

        if sf.time:
            for time in sf.time:
                if all((bf.upload_time - time > 0, bf.upload_time - time <= 86400)):
                    break
            else: 
                continue
        if sf.comment:
            for comment in sf.comment:
                if bf.comment and re_search(comment, bf.comment):
                    break
            else: 
                continue

        if sf.folder:
            for folder in sf.folder:
                if re_search(folder, bf.folder):
                    break
            else: 
                continue

        if sf.file_name: # todo: check SearchFilter with file_name and min_size.
            for file_name in sf.file_name:
                if re_search(file_name, bf.file_name):
                    break
            else: 
                continue

        if sf.file_salt:
            for file_salt in sf.file_salt:
                if re_search(file_salt, rbf.file_salt):
                    break
            else:
                continue

        if sf.verbyte:
            for verbyte in sf.verbyte:
                if verbyte == rbf.verbyte:
                    break
            else:
                continue

        yield bf

async def make_remote_box(
        ta: 'TelegramAccount', box_salt: bytes, box_path: str=DB_PATH, 
        BOX_IMAGE_PATH: str=BOX_IMAGE_PATH) -> 'RemoteBox':
    
    channel_name = 'tgbox: ' + box_path.split(path_sep)[-1]
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

def make_local_box(
        rb: 'RemoteBox', ta: 'TelegramAccount', mainkey: MainKey, 
        box_salt: bytes, box_path: str=DB_PATH) -> 'DecryptedLocalBox':
        
    make_db(box_path); init_db(
        ta.get_session(), rb._box_channel_id, 
        mainkey, box_salt, db_path=box_path,
        download_path=path_join(box_path, 'BOX_DATA', 'DOWNLOADS')
    )
    return EncryptedLocalBox(box_path).decrypt(mainkey)

def get_local_box(
        key: Optional[Union[MainKey, BaseKey]] = None, box_path: str=DB_PATH
        ) -> Union['EncryptedLocalBox', 'DecryptedLocalBox']:
    '''
    Returns LocalBox.
    
    key (`MainKey`, `BaseKey`, optional):
        Returns `DecryptedLocalBox` if specified,
        `EncryptedLocalBox` otherwise (default).
        
        You can specify `key` as `BaseKey` if it's
        was cloned from `RemoteBox` and has BOX_DATA/MAINKEY
        file. If it's your LocalBox, then use `MainKey`.
    
    box_path (`str`, optional):
        Path to the LocalBox DB.
        `.constants.DB_PATH` by default.
    '''
    if key:
        return EncryptedLocalBox(box_path=box_path).decrypt(key)
    else:
        return EncryptedLocalBox(box_path=box_path)

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

        self._box_salt = None # We can't use await in __init__, 
                              # ^ so you must call get_box_salt for first.

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
    
    @property
    def box_salt(self) -> bytes:
        '''You may need to call `get_box_salt` firstly.'''
        return self._box_salt
    
    async def get_box_salt(self) -> bytes:
        '''box_salt will be cached after first func call.'''
        if not self._box_salt:
            full_rq = await self._ta.TelegramClient(
                GetFullChannelRequest(channel=self._box_channel)
            )
            self._box_salt = b64decode(full_rq.full_chat.about)
            
        return self._box_salt
    
    async def clone(
            self, mainkey: Union[MainKey, ImportKey],
            basekey: BaseKey, clone_path: str='') -> 'DecryptedLocalBox':
        '''
        '''
        db_path = make_db(path_join(
            clone_path, self._box_channel.title.split(': ')[1]
        ))
        box_salt = self._box_salt if self._box_salt else await self.get_box_salt()
        last_file_id = (await self._ta.TelegramClient.get_messages(self._box_channel))[0].id
        
        box_cr_time = await self._ta.TelegramClient.get_messages(self._box_channel, ids=1)
        box_cr_time = int(box_cr_time.date.timestamp())
        
        dlb = EncryptedLocalBox(init_db(
            session=self._ta.get_session(), box_channel_id=self._box_channel_id,
            mainkey=mainkey, box_salt=box_salt, db_path=db_path, basekey=basekey,
            download_path=path_join(db_path, 'BOX_DATA', 'DOWNLOADS'),
            box_cr_time=box_cr_time, last_file_id=last_file_id
        )).decrypt(basekey)
        
        async for drbf in self.files(key=mainkey, decrypt=True, reverse=True):
            await dlb.import_file(drbf, foldername=drbf.folder)
            
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
            
    async def push_file(
            self, dlbfi: 'DecryptedLocalBoxFile', 
            mainkey: Optional[MainKey] = None
            ) -> 'DecryptedRemoteBoxFile':
        '''
        Encrypts & Uploads `DecryptedLocalBoxFile` to the `RemoteBox`.
        
        dlbfi (`DecryptedLocalBoxFile`):
            File to upload.
        
        mainkey (`MainKey`, optional):
            Mainkey of your Box. Will be used to update
            info about local file (i.e ID). Must be specified
            if `not isinstance(dlbfi._key, MainKey)`, typically 
            you shouldn't worry about this.
        '''
        try:
            mainkey = mainkey if mainkey else dlbfi._key
            assert isinstance(mainkey, MainKey)
        except (AttributeError, AssertionError):
            raise ValueError('You need to specify mainkey.') from None
            
        datastring = dump_to_datastring((
            dlbfi._elbfi._size, dlbfi._elbfi._file_iv, 
            dlbfi._file_salt, dlbfi._elbfi._comment,
            b64decode(dlbfi._elbfi._folder), 
            dlbfi._elbfi._duration, VERSION_BYTE
        ))        
        e = aes_encrypt(
            dlbfi._push_data, dlbfi._filekey, 
            dlbfi._file_iv, concat_iv=False
        )
        oe = OpenPretender(e)
        if dlbfi.preview:
            oe.concat_preview(
                encrypt_preview(dlbfi.preview, dlbfi._filekey)
            )
        ifile = await self._ta.TelegramClient.upload_file(
            oe, file_name=dlbfi._elbfi._file_name, part_size_kb=512,
            file_size = dlbfi._size
        )
        file_message = await self._ta.TelegramClient.send_file(
            self._box_channel, file=ifile, silent=True,
            caption=datastring, force_document=True
        )        
        file_path = path_join(
            dlbfi._box_path, dlbfi._elbfi._folder, 
            dlbfi._elbfi._file_name
        )
        current_time = int(file_message.date.timestamp())
        current_time_enc = b''.join(aes_encrypt(int_to_bytes(current_time), dlbfi._filekey))
        
        post_id = file_message.id
        post_id_enc = b''.join(aes_encrypt(int_to_bytes(post_id), dlbfi._filekey))
        post_id_enc_mainkey = b''.join(aes_encrypt(int_to_bytes(post_id), mainkey))
        
        with open(path_join(file_path, 'UPLOAD_TIME'),'wb') as f:
            f.write(current_time_enc)
        
        with open(path_join(file_path, 'ID'),'wb') as f:
            f.write(post_id_enc)
        
        with open(path_join(dlbfi._box_path,'BOX_DATA','LAST_FILE_ID'),'wb') as f:
            f.write(post_id_enc_mainkey)
        
        dlbfi._elbfi._upload_time = current_time_enc
        dlbfi._upload_time = current_time
        
        dlbfi._elbfi._id = post_id_enc
        dlbfi._id = post_id
        
        return EncryptedRemoteBoxFile(
            file_message, self._ta
        ).decrypt(mainkey)
    
    async def get_file(
            self, id: int, key: Optional[Union[MainKey, FileKey, ImportKey]] = None,
            dlb: Optional['DecryptedLocalBox'] = None, decrypt: bool=False)\
            -> Union['EncryptedRemoteBoxFile', 'DecryptedRemoteBoxFile', None]:
        '''
        Returns file from the RemoteBox by the given ID.
        ...
        '''     
        if decrypt and not any((key, dlb)):
            raise ValueError(
                'You need to specify key or dlb to be able to decrypt.'
            )
        key = key if (key or not dlb) else dlb._mainkey
        
        async for rbf in self.files(key, dlb=dlb, decrypt=decrypt, ids=id): 
            pass # Will iter only over one file
        return rbf # May raise UnboundLocalError if there is no file with specified ID.

    async def files(
            self, key: Optional[Union[MainKey, FileKey]] = None, dlb: Optional['DecryptedLocalBox'] = None, *, 
            ignore_errors: bool=True, return_imported_as_erbf: bool=False, limit: Optional[int] = None, 
            offset_id: int=0, max_id: int=0, min_id: int=0, add_offset: int=0, search: Optional[str] = None, 
            from_user: Optional[Union[str, int]] = None, wait_time: Optional[float] = None, 
            ids: Optional[Union[int, List[int]]] = None, reverse: bool=False, decrypt: bool=False
            ) -> Generator[Union['EncryptedRemoteBoxFile', 'DecryptedRemoteBoxFile'], None, None]:
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
            will use filekey from the `FILE_KEY` file.
            
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
            `RemoteBox` file and you don't want to specify dlb.
        
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
                
            if m.document: # May raise error if you specified file that doesn't exist.
                try:
                    if decrypt:
                        try:
                            rbf = EncryptedRemoteBoxFile(m, self._ta).decrypt(key)
                        except ValueError as e: # Padding incorrect, in case of imported file
                            if return_imported_as_erbf and not dlb:
                                rbf = EncryptedRemoteBoxFile(m, self._ta)
                            elif ignore_errors and not dlb:
                                continue
                            else:
                                if dlb:
                                    dlb_file = dlb.get_file(m.id, decrypt=True)
                                    if not dlb_file:
                                        if return_imported_as_erbf: 
                                            rbf = EncryptedRemoteBoxFile(m, self._ta)
                                        elif ignore_errors:
                                            continue
                                        else:
                                            raise e
                                    else:
                                        rbf = EncryptedRemoteBoxFile(
                                            m, self._ta).decrypt(dlb_file._filekey)
                                else: 
                                    raise e
                    else:
                        rbf = EncryptedRemoteBoxFile(m, self._ta)
                    yield rbf
                except IndexError: # Not Tgbox file (can't parse datastring).
                    pass
    
    async def get_requestkey(self, mainkey: MainKey) -> RequestKey:
        '''
        Returns `RequestKey` for this Box. 
        
        mainkey (`MainKey`, optional):
            Mainkey of this RemoteBox.
        '''
        channel_info = await self._ta.TelegramClient(
            GetFullChannelRequest(channel=self._box_channel)
        )
        box_salt = b64decode(channel_info.full_chat.about)
        return make_requestkey(mainkey, box_salt=box_salt)

    async def get_sharekey(
            self, mainkey: MainKey, 
            reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this box.
        
        mainkey (`MainKey`, optional):
            Mainkey of this RemoteBox.
        
        reqkey (`RequestKey`, optional):
            User's `RequestKey`. If isn't specified
            returns `ShareKey` of this box without
            encryption, so anyone with this key can
            decrypt **ALL** files in your `RemoteBox`.
        '''
        channel_info = await self._ta.TelegramClient(
            GetFullChannelRequest(channel=self._box_channel)
        )
        box_salt = b64decode(channel_info.full_chat.about)
        
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
        
        self._message = sended_file
        self._id = sended_file.id
        self._file = sended_file.file
        
        self._ta = ta
        self._cache_preview = cache_preview
        
        self._file_name = self._file.name
        self._box_channel_id = sended_file.peer_id.channel_id
        
        self._datastring = sended_file.message
        r_datastring = restore_datastring(self._datastring)
        
        self._time = int(self._message.date.timestamp())
        self._size = r_datastring[0]
        self._file_iv = r_datastring[1] # May raise IndexError, then we 
        self._file_salt = r_datastring[2] # ^ should ignore this as a non tgbox file.
        self._comment = r_datastring[3]
        self._folder = b64encode(r_datastring[4]).decode()
        self._duration = r_datastring[5]
        self._version_byte = r_datastring[6]
        
        self._file_size = self._file.size
        self._preview = None
        
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
    def exported(self) -> bool:
        '''
        Returns `True` if file was exported
        from other RemoteBox. `False` otherwise.
        .'''
        return self._exported
    
    @property
    def version_byte(self) -> bytes:
        '''Returns version byte.'''
        return self._version_byte
    
    @property
    def upload_time(self) -> int:
        return self._time
    
    @property
    def size(self) -> Union[bytes, int]:
        '''
        Returns bytes from `EncryptedRemoteBoxFile`
        and int from `DecryptedRemoteBoxFile`.
        '''
        return self._size
    
    @property
    def file_size(self) -> Union[bytes, int]:
        '''
        Returns size of the `File` from `Message`
        object. 
        '''
        return self._file_size
    
    @property
    def duration(self) -> Union[bytes, float]:
        '''
        Returns bytes from `EncryptedRemoteBoxFile`
        and float from `DecryptedRemoteBoxFile`.
        '''
        return self._duration
    
    @property
    def file_iv(self) -> bytes:
        '''Returns AES CBC IV for this file.'''
        return self._file_iv
    
    @property
    def comment(self) -> bytes:
        '''Returns file comment.'''
        return self._comment
    
    @property
    def folder(self) -> str:
        '''Returns folder name this file belongs to.'''
        return self._folder
    
    @property
    def file_salt(self) -> bytes:
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
    def file_name(self) -> str:
        '''
        Returns remote file name.
        '''
        return self._file_name
    
    @property
    def box_channel_id(self) -> File:
        '''
        Returns ID of the Box Channel.
        '''
        return self._box_channel_id
    
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
        
    async def get_preview(self) -> bytes:
        '''
        Returns file preview.
        
        If you call this on `EncryptedRemoteBoxFile` then
        there is no guarantee that this function will return
        preview, because we don't know if it was added or
        not, it can be just first 5008 of encrypted file.
        
        If you call this on `DecryptedRemoteBoxFile` then
        there is guarantee that you will recieve decrypted
        preview or zero bytes (`b''`) as return.
        
        If your class has `cache_preview` setted to `True` then
        after first call to Telegram servers it will be
        cached in object (max ~5KB), otherwise not.
        '''
        if self._preview:
            return self._preview
        else:
            async for preview in self._ta.TelegramClient.iter_download(
                self._message.document, offset=0, request_size=5008):
                    if hasattr(self, '_filekey'):
                        try:
                            maybe_preview = decrypt_preview(preview.tobytes(), self._filekey)
                            assert maybe_preview[:2 ] == b'\xff\xd8' # JPEG start prefix.
                            assert maybe_preview[-2:] == b'\xff\xd9' # JPEG end prefix.
                            preview = maybe_preview
                        except (ValueError, AssertionError):
                            preview = b'' # Not preview
                    if self._cache_preview:
                        self._preview = preview
                    return preview if isinstance(preview, bytes) else preview.tobytes()
    
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
    
    def get_requestkey(self, mainkey: Optional[MainKey] = None) -> RequestKey:
        '''
        Returns `RequestKey` for this file. May raise `ValueError` if
        file isn't decrypted and `mainkey` isn't specified.
        '''
        try:
            mainkey = mainkey if mainkey else self._key
            assert isinstance(mainkey, MainKey)
        except (AttributeError, AssertionError):
            raise ValueError('You need to specify mainkey.') from None
        
        return make_requestkey(mainkey, file_salt=self._file_salt)
    
    def decrypt(self, key: Union[MainKey, FileKey, ImportKey]) -> 'DecryptedRemoteBoxFile':
        return DecryptedRemoteBoxFile(self, key)
    
class DecryptedRemoteBoxFile(EncryptedRemoteBoxFile):
    def __init__(
            self, erbf: EncryptedRemoteBoxFile, 
            key: Union[MainKey, FileKey, ImportKey]):
        
        self._key = key
        self._erbf = erbf
        
        super().__init__(
            erbf._message, erbf._ta, 
            erbf._cache_preview
        )
        if isinstance(key, (FileKey, ImportKey)):
            self._filekey, folder_iv = key, None
        else:
            self._filekey = make_filekey(self._key, self._file_salt)
            folder_iv = make_folder_iv(self._key)
        
        file_folder_iv = make_folder_iv(self._filekey)
        
        if folder_iv:
            self._folder = b''.join(aes_decrypt(b64decode(self._folder), key, folder_iv)).decode()
        else:
            self._folder = 'NO_FOLDER'
            
        self._file_name = b''.join(aes_decrypt(b64decode(
            self._file_name), self._filekey, file_folder_iv)).decode()        
        
        self._size = bytes_to_int(b''.join(aes_decrypt(self._size, self._filekey)))
        self._duration = bytes_to_float(b''.join(aes_decrypt(self._duration, self._filekey)))
        self._file_iv = b''.join(aes_decrypt(self._file_iv, self._filekey))
        
        if self._comment:
            self._comment = b''.join(aes_decrypt(self._comment, self._filekey)).decode()
        else:
            self._comment = b''
    
    async def download_preview(
            self, *, outfile: Union[str, BinaryIO] = DOWNLOAD_PATH) -> BinaryIO:
        '''
        Downloads and saves preview of the 
        remote box file to the `outfile`.
        
        If `cache_preview` is enabled, then preview
        will be cached in object after you call this func.
        
        Will raise `Exception` if this file has no preview.
        
        oufile (`str`, `BinaryIO`, optional):
            Path or File-like object to which file will be downloaded.
            `.constants.DOWNLOAD_PATH` by default.
            
            If `outfile` has `.write()` method then we will use it.
        '''
        if isinstance(outfile, str):
            if not path_exists(path_join(outfile, self._folder)):
                makedirs(path_join(outfile, self._folder))
                
            file_name = f'preview_{self._file_name}.jpg'
            outfile = open(path_join(outfile, self._folder, file_name), 'wb')
            
        elif not (isinstance(outfile, BinaryIO) or hasattr(outfile, 'write')):
            raise TypeError('outfile not Union[BinaryIO, str].')
        
        preview = await self.get_preview()
        if not preview:
            raise Exception('This file has no preview.')
        else:
            outfile.write(preview)
        
    async def download(
            self, *, outfile: Union[str, BinaryIO] = DOWNLOAD_PATH, 
            hide_folder: bool=False, hide_name: bool=False,
            decrypt: bool=True, ignore_preview: bool=False,
            skip_preview: bool=False, offset: int=0,  
            request_size: int=524288, box_path: str=DB_PATH) -> BinaryIO:
        '''
        Downloads and saves remote box file to the `outfile`.
        
        oufile (`str`, `BinaryIO`, optional):
            Path or File-like object to which file will be downloaded.
            `.constants.DOWNLOAD_PATH` by default.
            
            If `outfile` has `.write()` method then we will use it.
        
        hide_folder (`bool`, optional):
            Saves to folder which this file belongs to if False,
            (default) otherwise to `outfile/UNKNOWN_FOLDER`.
            
            Doesn't create any folders if `isinstance(outfile, BinaryIO)`.
        
        hide_name (`bool`, optional):
            Saves file with encrypted name if True, with
            decrypted if False (default).
            
            Doesn't create any folders if `isinstance(outfile, BinaryIO)`.
        
        decrypt (`bool`, optional):
            Decrypts file if True (default).
        
        ignore_preview (`bool`, optional):
            If set to `False`, tries to decrypt first 5008 bytes
            of the file to identify preview. If you sure that
            your `DecryptedRemoteBoxFile` hasn't preview, then
            you can set this to `True`. Will be ignored if 
            file size is <= 5008. `False` by default.
        
        skip_preview (`bool`, optional):
            If set to `True`, skips first 5008 bytes
            of the file. You can set it to `True` if you
            sure that this file has preview. Will be ignored
            if file size is <= 5008. `False` by default.
            
            `offset` will be ignored if you set this to `True`.
        
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
        
        box_path (`str`, optional):
            Path to Box DB Folder. `.constants.DB_PATH` by default.
        '''
        assert not all((ignore_preview, skip_preview)) # Please choose one kwarg.
        
        if decrypt:
            aws = AESwState(self._filekey, self._file_iv)
        
        if isinstance(outfile, str):
            folder = 'UNKNOWN_FOLDER' if hide_folder else self._folder
            name = self._erbf._file_name if hide_name else self._file_name
            
            if not path_exists(path_join(outfile, self._folder)):
                makedirs(path_join(outfile, self._folder))
                
            outfile = open(path_join(outfile, folder, name), 'wb')
            
        elif isinstance(outfile, BinaryIO) or hasattr(outfile, 'write'):
            pass # We already can write (at least hope with us).
        else:
            raise TypeError('outfile not Union[BinaryIO, str].')
        
        offset = 0 if skip_preview else offset
        
        iter_down = self._ta.TelegramClient.iter_download(
            self._message.document, offset=offset, 
            request_size=request_size
        )
        preview_bypassed = False
        async for chunk in iter_down:
            if not any((self._size <= 5008, ignore_preview, skip_preview, preview_bypassed)):
                try:
                    maybe_preview = decrypt_preview(chunk[:5008], self._filekey)
                    assert maybe_preview[:2 ] == b'\xff\xd8' # JPEG start prefix.
                    assert maybe_preview[-2:] == b'\xff\xd9' # JPEG end prefix.
                    chunk = chunk[5008:]
                except (ValueError, AssertionError):
                    pass # Not preview
                
                preview_bypassed = True
            
            if skip_preview and not preview_bypassed:
                chunk = chunk[5008:]
            
            chunk = aws.decrypt(chunk) if decrypt else chunk
            outfile.write(chunk)

        if decrypt:
            outfile.write(aws.finalize())  
        
        if isinstance(self._key, FileKey):
            folder = b64encode(open(path_join(
                box_path,'BOX_DATA','NO_FOLDER'),'rb').read()).decode()
        else:
            folder = self._erbf._folder
            
        ff_path = path_join(
            box_path, folder, self._erbf._file_name
        )
        if path_exists(ff_path):
            with open(path_join(ff_path,'FILE_PATH'),'wb') as f:
                f.write(b''.join(aes_encrypt(outfile.name.encode(), self._filekey)))

        return outfile
    
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this file.
        
        reqkey (`RequestKey`, optional):
            User's `RequestKey`. If isn't specified
            returns `ShareKey` of this file without
            encryption, so anyone with this key can
            decrypt this remote file.
        '''
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, filekey=self._filekey, 
                file_salt=self._file_salt
            )
        else:
            return make_sharekey(filekey=self._filekey)
        
class EncryptedLocalBox:
    def __init__(self, box_path: str=DB_PATH):
        self._box_path = box_path
        self._box_salt = open(path_join(box_path,'BOX_DATA','BOX_SALT'),'rb').read()
        
        self._session = open(path_join(box_path,'BOX_DATA','SESSION'),'rb').read()
        self._box_channel_id = open(path_join(box_path,'BOX_DATA','BOX_CHANNEL_ID'),'rb').read()
        self._box_cr_time = open(path_join(box_path,'BOX_DATA','BOX_CR_TIME'),'rb').read()
        self._last_file_id = open(path_join(box_path,'BOX_DATA','LAST_FILE_ID'),'rb').read()
            
    def __hash__(self) -> int:
        return hash((self._box_salt, self._session))
        # ^ Session will be different in Enc or Dec classes.
        
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __repr__(self) -> str:
        type_ = 'DecryptedLocalBox' if hasattr(self, '_mainkey') else 'EncryptedLocalBox'    
        return f'{type_}("{self._box_path}") # LAST_FILE_ID: {self._last_file_id} at {hex(id(self))}'
    
    @property
    def box_path(self) -> str:
        return self._box_path
    
    @property
    def box_salt(self) -> bytes:
        return self._box_salt
    
    @property
    def session(self) -> Union[bytes, str]:
        return self._session
    
    @property
    def box_channel_id(self) -> Union[bytes, str]:
        return self._box_channel_id
    
    @property
    def box_cr_time(self) -> Union[bytes, str]:
        return self._box_cr_time
    
    @property
    def last_file_id(self) -> Union[bytes, str]:
        return self._last_file_id
    
    def folders(self) -> Union['EncryptedLocalBoxFolder','DecryptedLocalBoxFolder']:
        '''
        Yields `EncryptedLocalBoxFolder` from `EncryptedLocalBox` and
        `DecryptedLocalBoxFolder` from `DecryptedLocalBox`.
        '''
        decrypt = True if hasattr(self, '_mainkey') else False
        
        for folder in listdir(self._box_path):
            if folder != 'BOX_DATA':
                if decrypt:
                    yield EncryptedLocalBoxFolder(
                        path_join(self._box_path, folder)
                    ).decrypt(self._mainkey)
                else:
                    yield EncryptedLocalBoxFolder(
                        path_join(self._box_path, folder)
                    )
    def get_folder(self, foldername: str) ->\
            Union['EncryptedLocalBoxFolder','DecryptedLocalBoxFolder']:
        '''
        Returns folder by given foldername.
        
        foldername (`str`):
            Name of the folder. Must be encoded with `urlsafe_b64encode` if
            encrypted. Returns `EncryptedLocalBoxFolder` from `EncryptedLocalBox` 
            and `DecryptedLocalBoxFolder` from `DecryptedLocalBox`.
        '''
        for folder in self.folders():
            if folder.foldername == foldername:
                return folder
    
    def get_file(
            self, id: Union[bytes, int], 
            mainkey: Optional[MainKey] = None, decrypt: bool=False) ->\
            Union['DecryptedLocalBoxFile','EncryptedLocalBoxFile', None]:
        '''
        '''
        if decrypt and not any((hasattr(self, '_mainkey'), mainkey)):
            raise ValueError('You must specify mainkey in Encrypted* classes.')
        else: mainkey = mainkey if (mainkey and not decrypt) else self._mainkey
            
        for folder in self.folders():
            for file in folder.files(mainkey, decrypt=decrypt):
                if file.id == id: return file
    
    async def search_file(self, sf: SearchFilter, mainkey: Optional[MainKey] = None):
        mainkey = mainkey if (not hasattr(self, '_mainkey') and not mainkey) else self._mainkey
        async for file in _search_func(sf, lb=self, mainkey=mainkey):
            yield file
        
    def get_requestkey(self, mainkey: Optional[MainKey] = None) -> RequestKey:
        '''
        Returns `RequestKey` for this Box. May raise `ValueError` if
        Box isn't decrypted and `mainkey` isn't specified.
        '''
        try:
            mainkey = mainkey if mainkey else self._key
            assert isinstance(mainkey, MainKey)
        except (AttributeError, AssertionError):
            raise ValueError('You need to specify mainkey.') from None
        return make_requestkey(mainkey, box_salt=self._box_salt)
    
    def decrypt(self, key: Union[MainKey, ImportKey, BaseKey]) -> 'DecryptedLocalBox':
        return DecryptedLocalBox(self, key)

class DecryptedLocalBox(EncryptedLocalBox):
    def __init__(
            self, elb: EncryptedLocalBox, 
            key: Union[MainKey, ImportKey, BaseKey]):
        
        super().__init__(elb._box_path)
        
        if isinstance(key, (MainKey, ImportKey)):
            self._mainkey = key
            
        elif isinstance(key, BaseKey):
            true_mainkey = path_join(self._box_path,'BOX_DATA','MAINKEY')
            if path_exists(true_mainkey):
                true_mainkey = open(true_mainkey,'rb').read()
                self._mainkey = MainKey(b''.join(aes_decrypt(true_mainkey, key)))
            else:
                raise TypeError('Can\'t use BaseKey, there is no MAINKEY file.')
        else:
            raise TypeError('key is not Union[MainKey, ImportKey, BaseKey]')
        
        self._elb = elb
        
        self._session = b''.join(aes_decrypt(self._session, key)).decode()
        self._box_channel_id = bytes_to_int(b''.join(aes_decrypt(self._box_channel_id, self._mainkey)))
        self._box_cr_time = bytes_to_int(b''.join(aes_decrypt(self._box_cr_time, self._mainkey)))
        
        if self._last_file_id:
            self._last_file_id = bytes_to_int(b''.join(aes_decrypt(self._last_file_id, self._mainkey)))
        else:
            self._last_file_id = 0
            
    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            '''This function was inherited from `EncryptedLocalBox` '''
            '''and cannot be used on `DecryptedLocalBox`.'''
        )
    async def add_file(
            self, file: Union[BinaryIO, BytesIO, bytes], foldername: str='NO_FOLDER',
            comment: bytes=b'', make_preview: bool=True,
            ignore_limit_errors: bool=False) -> Union['EncryptedLocalBoxFile', None]:
        '''
        file (`BinaryIO`, `BytesIO`):
            `file` data to add to the LocalBox. In most
            cases it's just opened file. If you want to upload
            something else, then you need to implement class
            that have `read` & `name` methods.
            
            The method needs to know size of the `file`, so
            it will try to ask system what size of file on path
            `file.name`. If it's impossible, then program tries to
            get size by `len()` (from `__len__` dunder). If both fails,
            it tries to get `len(file.read())` (with load to RAM).
            
            File name length must be <= 45 symbols.
            If file has no `name` then it will be `urandom(6).hex()`
            
            File can't be empty, program will raise `ValueError`
            if you will try to upload it. If `ignore_limit_errors == True`,
            then file data will be extended to 1 byte, b'\x00'.
            
        foldername (`str`, optional):
            Folder to add this file to.
        
        comment (`bytes`, optional):
            File comment. Must be <= 300 bytes.
        
        make_preview (`bool`, optional):
            Will add file preview to the encrypted 
            file if `True` (default).
        
        ignore_limit_erors (`bool`, optional):
            Will ignore all `ValueError`s if file
            data won't fit the limit. I.e, if filename
            length is more than 45, we will cut it to 
            fit the limit. `False` by default.
        '''
        # todo: set foldername length limit.
        
        if len(comment) > 300:
            if not ignore_limit_errors:
                raise ValueError('Comment length must be <= 300 bytes.')
            else:
                comment = comment[:300]
                
        file_salt, file_iv = urandom(32), urandom(16)
        filekey = make_filekey(self._mainkey, file_salt)
        
        if hasattr(file, 'name'):
            file_name = file.name.split(path_sep)[-1]
            if len(file_name) > 45:
                if not ignore_limit_errors:
                    raise ValueError('File name length must be <= 45 symbols.')
                else:
                    file_name = file_name[:45]
        else:
            file_name = urandom(6).hex()
        try:
            file_size = getsize(file.name)
        except:
            if hasattr(file, 'read'):
                file_data = file.read()
                file_size = len(file_data)
                file = BytesIO(file_data)
                
            elif isinstance(file, bytes):
                file_size = len(file)
                file = BytesIO(file)
            else:
                raise ValueError('file is not (bytes, BinaryIO).')
        
        if file_size == 0:
            if ignore_limit_errors:
                file_size, file = 1, BytesIO(b'\x00')
            else:
                raise ValueError('File can\'t be empty.')
        
        ff = make_db_file_folder(
            file_name, foldername, self._mainkey, 
            filekey, db_path=self._box_path
        )
        preview, duration = b'', b'\x00'*4
        
        if make_preview:
            gtype = guess_type(file_name)
            if gtype[0]:
                type_ = gtype[0].split('/')[0]

                if type_ in ('audio','video'):
                    try:
                        preview = await make_media_preview(file.name)
                    except (TypeError, AttributeError):
                        preview = b''

                    duration = float_to_bytes(await get_media_duration(file.name))

                elif type_ == 'image':
                    try:
                        preview = await make_image_preview(file.name)
                    except (TypeError, AttributeError):
                        preview = b''

                    duration = b'\x00'*4
        
        if len(preview) > 5008:
            preview = b'' # todo: Maybe we need to somehow limit image size.
            
        data = {
            'ID': b'', # Empty because file isn't uploaded.
            'UPLOAD_TIME': b'', # Empty because file isn't uploaded.
            'FILE_PATH': b'', # Empty because file isn't uploaded.
            'FILE_KEY': b'', # Used if file imported from other box.
            'COMMENT': comment,
            'SIZE': int_to_bytes(file_size),
            'PREVIEW': preview,
            'DURATION': duration, # Always not empty, but if b'\x00'*4 then isn't media.
            'FILE_SALT': file_salt,
            'FILE_IV': file_iv,
            'VERBYTE': VERSION_BYTE
        }
        for k,v in data.items():
            with open(path_join(ff, k),'wb') as f:
                if v: # If `not v` then we only create file.
                    if k not in ('FILE_SALT', 'VERBYTE'): # FILE_SALT and VERBYTE isn't encrypted.
                        v = b''.join(aes_encrypt(v, filekey))
                    f.write(v)

        return EncryptedLocalBoxFile(
            file_path=ff, push_data=file).decrypt(self._mainkey)
    
    async def import_file(
            self, drbf: DecryptedRemoteBoxFile,
            foldername: str='NO_FOLDER') -> 'DecryptedLocalBoxFile':

        upload_time = b''.join(aes_encrypt(int_to_bytes(drbf.upload_time), drbf._filekey))
        id = b''.join(aes_encrypt(int_to_bytes(drbf.id), drbf._filekey))
        
        # v If filekeys isn't equal then this file from other box, and we need to write FILE_KEY.
        if drbf._filekey != make_filekey(self._mainkey, drbf._file_salt):
            filekey = b''.join(aes_encrypt(drbf._filekey.key, self._mainkey))
        else:
            filekey = b''
        
        preview = await drbf.get_preview()
        if preview:
            preview = b''.join(aes_encrypt(preview, drbf._filekey))
        
        data = {
            'ID': id,
            'UPLOAD_TIME': upload_time,
            'FILE_KEY': filekey,
            'COMMENT': drbf._erbf._comment,
            'SIZE': drbf._erbf._size,
            'PREVIEW': preview,
            'DURATION': drbf._erbf._duration,
            'FILE_SALT': drbf._erbf._file_salt,
            'FILE_IV': drbf._erbf._file_iv,
            'VERBYTE': drbf._erbf._version_byte,
            'FILE_PATH': b''
        }
        ff = make_db_file_folder(
            drbf.file_name, foldername, self._mainkey, 
            drbf._filekey, db_path=self._box_path
        )
        for k,v in data.items():
            with open(path_join(ff, k),'wb') as f:
                if v: f.write(v)

        return EncryptedLocalBoxFile(file_path=ff).decrypt(drbf._filekey)
    
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
        Returns `ShareKey` for this Box.
        
        reqkey (`RequestKey`, optional):
            User's `RequestKey`. If isn't specified
            returns `ShareKey` of this box without
            encryption, so anyone with this key can
            decrypt **ALL** files in your `RemoteBox`.
        '''
        if reqkey:
            return make_sharekey(
                requestkey=reqkey, 
                mainkey=self._mainkey, 
                file_salt=self._box_salt
            )
        else:
            return make_sharekey(mainkey=self._mainkey)
    
    def make_folder(self, foldername: str) -> None:
        make_db_folder(foldername, self._mainkey)
        
class EncryptedLocalBoxFolder:
    def __init__(self, folder_path: str):
        self._folder_path = folder_path
        self._foldername = folder_path.split(path_sep)[-1]
    
    def __hash__(self) -> int:
        return hash((self._foldername, 22))
        # ^ Without 22 hash of str wil be equal to object's
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    @property
    def folder_path(self) -> str:
        '''Returns path to this folder.'''
        return self._folder_path
    
    @property
    def foldername(self) -> str:
        '''Returns folder name.'''
        return self._foldername
    
    def files(
            self, mainkey: Optional[Union[MainKey, ImportKey]] = None, decrypt: bool=True
            ) -> Union['EncryptedLocalBoxFile','DecryptedLocalBoxFile']:
        '''
        Yields every local file from this folder as `EncryptedLocalBoxFile`
        if we are in `EncryptedLocalBoxFolder`, `DecryptedLocalBoxFile` otherwise.
        '''
        try:
            if decrypt:
                mainkey = mainkey if mainkey else self._mainkey
                assert isinstance(mainkey, (MainKey, ImportKey))
        except (AssertionError, AttributeError):
            raise ValueError(
                '''Decryption on EncryptedLocalBoxFolder '''
                '''isn\'t allowed. Did you forget to specify mainkey?'''
            ) from None
            
        for file in listdir(self._folder_path):
            
            if file != 'FOLDER_CR_TIME':
                if decrypt:
                    yield EncryptedLocalBoxFile(
                        path_join(self._folder_path, file)
                    ).decrypt(mainkey)
                else:
                    yield EncryptedLocalBoxFile(
                        path_join(self._folder_path, file)
                    )
    def get_file(
            self, id: Union[int, bytes], mainkey: Optional[Union[MainKey, ImportKey]] = None, 
            decrypt: bool=True) -> Union['EncryptedLocalBoxFile','DecryptedLocalBoxFile',None]:
        '''
        Returns file by given ID.
        
        id (`int`, `bytes`):
            ID of the uploaded to `RemoteBox` file. Can
            be `bytes` to search for encrypted file, or `int`
            to search decrypted.
        
        mainkey (`MainKey`, `ImportKey`, optional):
            Mainkey of the Box. Must be specified if you
            search by `int` id on `EncryptedLocalBox`, or if
            you set `decrypt` kwarg as `True`.
            
        decrypt (`bool`, optional):
            Returns `DecryptedLocalBoxFile` if `True`
            (by default), `EncryptedLocalBoxFile` otherwise.
        '''
        try:
            if decrypt or isinstance(id, int):
                mainkey = mainkey if mainkey else self._mainkey
                assert isinstance(mainkey, (MainKey, ImportKey))
        except (AssertionError, AttributeError):
            raise ValueError(
                '''Decryption on EncryptedLocalBoxFolder '''
                '''isn\'t allowed. Did you forget to specify mainkey?'''
            ) from None
        decrypt_file = True if isinstance(id, int) else False            
        for file in self.files(mainkey, decrypt=decrypt_file):
            if file.id == id: return file
    
    def decrypt(self, mainkey: [MainKey, ImportKey]) -> 'DecryptedLocalBoxFolder':
        '''Returns decrypted by `mainkey` `DecryptedLocalBoxFolder`.'''
        return DecryptedLocalBoxFolder(self, mainkey)
    
    def delete(self, db_path: str=DB_PATH) -> None:
        '''
        Will delete this folder with all files from your LocalBox.
        All files will stay in `RemoteBox`, so you can restore
        all your folders via importing files.
        '''
        if hasattr(self, '_elbf'): # We're into DecryptedLocalBoxFolder
            rm_db_folder(self._elbf._foldername, db_path=db_path)
        else:
            rm_db_folder(self._foldername, db_path=db_path)

class DecryptedLocalBoxFolder(EncryptedLocalBoxFolder):
    def __init__(self, elbf: EncryptedLocalBoxFolder, mainkey: [MainKey, ImportKey]):
        super().__init__(elbf._folder_path)
        
        self._elbf = elbf
        self._mainkey = mainkey
        
        self._foldername = b''.join(aes_decrypt(
            b64decode(self._foldername), 
            mainkey, make_folder_iv(mainkey))).decode()
                
class EncryptedLocalBoxFile:
    def __init__(
            self, file_path: str, 
            push_data: Optional[BinaryIO] = None, 
            cache_preview: bool=True):
        
        self._file_path = file_path
        self._push_data = push_data
        self._cache_preview = cache_preview
        
        self._file_name = self._file_path.split(path_sep)[-1]
        self._folder = self._file_path.split(path_sep)[-2]
        self._box_path = file_path.split(path_sep)[-3]
        
        self._comment = open(path_join(self._file_path, 'COMMENT'),'rb').read()
        self._size = open(path_join(self._file_path, 'SIZE'),'rb').read()
        self._duration = open(path_join(self._file_path, 'DURATION'),'rb').read()
        self._id = open(path_join(self._file_path, 'ID'),'rb').read()
        self._upload_time = open(path_join(self._file_path, 'UPLOAD_TIME'),'rb').read()
        self._file_salt = open(path_join(self._file_path, 'FILE_SALT'),'rb').read()
        self._file_iv = open(path_join(self._file_path, 'FILE_IV'),'rb').read()
        self._filekey = open(path_join(self._file_path, 'FILE_KEY'),'rb').read()
        self._version_byte = open(path_join(self._file_path, 'VERBYTE'),'rb').read()
        self._exported = True if self._filekey else False
        
        self._file = None
        
        if cache_preview:
            with open(path_join(self._file_path, 'PREVIEW'),'rb') as f:
                self._preview = f.read()
        else:
            self._preview = None
    
    def __hash__(self) -> int:
        return hash(self._id)
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self.__hash__() == hash(other)
        ))
    def __repr__(self) -> str:
        return (
            f'''EncryptedLocalBoxFile('{self._file_path}', {self._push_data}) '''
            f'''# FILE_SALT: {self._file_salt.hex()} at {hex(id(self))}'''
        )
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
    def box_path(self) -> bool:
        return self._box_path
    
    @property
    def exported(self) -> bool:
        return self._exported
    
    @property
    def version_byte(self) -> str:
        return self._version_byte
    
    @property
    def file_path(self) -> str:
        return self._file_path

    @property
    def file_name(self) -> str:
        return self._file_name

    @property
    def folder(self) -> str:
        return self._folder

    @property
    def size(self) -> Union[bytes, int]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and int from `DecryptedLocalBoxFile`.
        '''
        return self._size
    
    @property
    def duration(self) -> Union[bytes, float]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and float from `DecryptedLocalBoxFile`.
        '''
        return self._duration
    
    @property
    def comment(self) -> bytes:
        '''Returns file comment.'''
        return self._comment

    @property
    def id(self) -> Union[bytes, int]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and int from `DecryptedLocalBoxFile`.
        '''
        return self._id
    
    @property
    def file_iv(self) -> bytes:
        '''
        Returns encrypted FILE_IV from `EncryptedLocalBoxFile`
        and decrypted FILE_IV from `DecryptedLocalBoxFile`.
        '''
        return self._file_iv

    @property
    def upload_time(self) -> Union[bytes, int]:
        '''
        Returns bytes from `EncryptedLocalBoxFile`
            and int from `DecryptedLocalBoxFile`.
        '''
        return self._upload_time

    @property
    def file_salt(self) -> bytes:
        '''
        Returns `FILE_SALT`.
        
        You can get decryption key for this file
        with `.crypto.make_filekey(mainkey, file_salt)`.
        '''
        return self._file_salt

    @property
    def preview(self) -> bytes:
        '''
        Returns file preview. If there is no
        preview then returns `b''`.
        '''
        if self._preview is None:
            with open(path_join(self._file_path, 'PREVIEW'),'rb') as f:
                preview = f.read()
                if self._cache_preview:
                    self._preview = preview
                return preview
        else:
            return self._preview
    
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
    
    def get_requestkey(self, mainkey: Optional[MainKey] = None) -> RequestKey:
        '''
        Returns `RequestKey` for this file. May raise `ValueError` if
        file isn't decrypted and `mainkey` isn't specified.
        '''
        try:
            mainkey = mainkey if mainkey else self._mainkey
        except AttributeError:
            raise ValueError('You need to specify mainkey in Encrypted* classes.') from None
        return make_requestkey(mainkey, file_salt=self._file_salt)

    def decrypt(self, key: Union[FileKey, ImportKey, MainKey]) -> 'DecryptedLocalBoxFile':
        return DecryptedLocalBoxFile(self, key)
    
    def delete(self, db_path: str=DB_PATH) -> None:
        '''
        Will delete this file from your LocalBox.
        You can re-import it from `RemoteBox` with
        `import_file`. To remove your file totally
        please use same function on RemoteBoxFile.
        '''
        self._file_name = self._file_path.split(path_sep)[-1]
        self._folder = self._file_path.split(path_sep)[-2]
        
        if hasattr(self, '_elbfi'): # We're into DecryptedLocalBoxFile
            rm_db_file_folder(self._elbfi._file_name, 
                self._elbfi._folder, db_path=db_path
            )
        else:
            rm_db_file_folder(self._file_name, 
                self._folder, db_path=db_path
            )
class DecryptedLocalBoxFile(EncryptedLocalBoxFile):
    def __init__(
            self, elbfi: EncryptedLocalBoxFile, 
            key: Union[FileKey, ImportKey, MainKey]):
        
        self._elbfi = elbfi
        self._key = key
        
        super().__init__(
            elbfi._file_path, elbfi._push_data, 
            elbfi._cache_preview
        )
        if isinstance(key, (FileKey, ImportKey)):
            self._filekey, folder_iv = key, None
        elif isinstance(key, MainKey) and self._filekey:
            self._filekey = FileKey(b''.join(aes_decrypt(self._filekey, self._key)))
            folder_iv = None
        else:
            self._filekey = make_filekey(self._key, self._file_salt)
            folder_iv = make_folder_iv(self._key)
        
        file_folder_iv = make_folder_iv(self._filekey)
        self._file_name = b''.join(aes_decrypt(b64decode(self._file_name), self._filekey, file_folder_iv)).decode()
        
        if folder_iv:
            self._folder = b''.join(aes_decrypt(b64decode(self._folder), self._key, folder_iv)).decode()
        else:
            self._folder = 'NO_FOLDER' # Can't decrypt foldername because we don't have mainkey
        
        try:
            path = open(path_join(self._file_path,'FILE_PATH'),'rb').read()
            path = b''.join(aes_decrypt(path, self._filekey)).decode()
            self._file = open(path, 'rb')
        except:
            self._file = None
        
        self._comment = b''.join(aes_decrypt(self._comment, self._filekey) if self._comment else b'')
        self._size = bytes_to_int(b''.join(aes_decrypt(self._size, self._filekey)))
        self._duration = bytes_to_float(b''.join(aes_decrypt(self._duration, self._filekey)))
        self._id = self._id if not self._id else bytes_to_int(b''.join(aes_decrypt(self._id, self._filekey)))
        self._file_iv = b''.join(aes_decrypt(self._file_iv, self._filekey))
        
        if self._upload_time:
            self._upload_time = bytes_to_int(b''.join(aes_decrypt(self._upload_time, self._filekey)))
        
        if self._preview:
            self._preview = b''.join(aes_decrypt(self._preview, self._filekey))
        
        self._download_path = DOWNLOAD_PATH
    
    def __repr__(self) -> str:
        elbfi_repr = repr(self._elbfi).split(' #')[0]
        mainkey_repr = repr(self._key).split(' #')[0]
        return (
            f'''DecryptedLocalBoxFile({elbfi_repr}, {mainkey_repr}) # ID: {self._id}, '''
            f'''SIZE: {self._size}, FILE_SALT: {self._file_salt.hex()} at {hex(id(self))}'''
        )
    @property
    def download_path(self) -> str:
        return self._download_path

    @property
    def preview(self) -> bytes:
        '''
        Returns file preview. If there is no preview 
        then returns `b''`. If `EncryptedLocalBoxFile`
        parent (`self._elbfi`) disabled `cache_preview`, then
        every call of this method will open & decrypt PREVIEW file.
        '''
        if self._preview:
            with open(path_join(self._file_path, 'PREVIEW'),'rb') as f:
                return b''.join(aes_decrypt(f.read(), self._filekey))
        else:
            return self._preview

    @staticmethod
    def decrypt() -> NoReturn:
        raise AttributeError(
            '''This function was inherited from `EncryptedLocalBoxFile` '''
            '''and cannot be used on `DecryptedLocalBoxFile`.'''
        )
    """ # TODO: NOFIX: TOREMOVE?
    async def get_remote(
            self, decrypt: bool=True,
            ta: Optional[TelegramAccount] = None,
            box_path: str=DB_PATH) -> Union[
                DecryptedRemoteBoxFile, 
                EncryptedRemoteBoxFile, None
        ]:
        '''
        Returns `DecryptedRemoteBoxFile` by default.
        `EncryptedRemoteBoxFile` if `bool(decrypt) != 1`.
        
        Returns `None` if file isn't uploaded.
        '''
        if not self._id:
            return None
        else:
            rb = await get_remote_box(ta=ta)
            return await rb.get_file(
                self._id, self._filekey, decrypt=decrypt
            )
    """
    def get_sharekey(self, reqkey: Optional[RequestKey] = None) -> ShareKey:
        '''
        Returns `ShareKey` for this file.
        
        reqkey (`RequestKey`, optional):
            User's `RequestKey`. If isn't specified
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
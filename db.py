from os.path import exists, getsize, join as path_join
from base64 import (
    urlsafe_b64encode as b64encode,  # We use urlsafe base64.
    urlsafe_b64decode as b64decode
) 
from hashlib import sha256
from os import mkdir
from time import time
from shutil import rmtree
from typing import Optional, Union

from .tools import int_to_bytes, bytes_to_int, make_folder_iv
from .constants import DB_PATH, DOWNLOAD_PATH
from .crypto import aes_encrypt, aes_decrypt
from .keys import Key, MainKey, FileKey, ImportKey, BaseKey

def get_box_salt(db_path: str=DB_PATH) -> bytes:
    '''Returns box salt. Note that for first you need to make LocalBox.'''
    return open(path_join(db_path,'BOX_DATA','BOX_SALT'),'rb').read() # Make box firstly.

def get_box_channel_id(mainkey: Optional[MainKey] = None, db_path: str=DB_PATH) -> Union[bytes, int]:
    '''Returns box channel id. If `mainkey` specified then tries to decrypt.'''
    
    box_channel_id = open(path_join(db_path,'BOX_DATA','BOX_CHANNEL_ID'),'rb').read()
    if mainkey:
        return bytes_to_int(b''.join(aes_decrypt(box_channel_id, mainkey)))
    else:
        return box_channel_id
    
def get_box_cr_time(mainkey: Optional[MainKey] = None, db_path: str=DB_PATH) -> bytes:
    '''Returns box creation time. If `mainkey` specified then tries to decrypt.'''

    box_cr_time = open(path_join(db_path,'BOX_DATA','BOX_CR_TIME'),'rb').read()
    if mainkey:
        return b''.join(aes_decrypt(box_cr_time, mainkey))
    else:
        return box_cr_time
    
def get_last_file_id(mainkey: Optional[MainKey] = None, db_path: str=DB_PATH) -> bytes:
    '''
    Returns id of the last file in the box. May be useful for detecting new files. 
    If `mainkey` specified then tries to decrypt.
    '''
    last_file_id = open(path_join(db_path,'BOX_DATA','LAST_FILE_ID'),'rb').read()
    if mainkey:
        return b''.join(aes_decrypt(last_file_id, mainkey))
    else:
        return last_file_id

def get_session(mainkey: Optional[MainKey] = None, db_path: str=DB_PATH) -> bytes:
    '''Returns encrypted session. If `mainkey` specified then tries to decrypt.'''
    
    session = open(path_join(db_path,'BOX_DATA','SESSION'),'rb').read()
    if mainkey:
        return b''.join(aes_decrypt(session, mainkey)).decode()
    else:
        return session
       
def make_db(db_path: str=DB_PATH) -> str:
    '''Creates `db_path` DIR and returns `db_path`'''
    mkdir(db_path); return db_path

def init_db(
        session: str, box_channel_id: int, mainkey: Union[MainKey, ImportKey],
        box_salt: bytes, db_path: str=DB_PATH, download_path: str=DOWNLOAD_PATH, 
        basekey: Optional[BaseKey] = None, box_cr_time: Optional[int] = None) -> str:
    '''
    Will init DB with SESSION, BOX_SALT, BOX_CR_TIME & etc.
    If you want to clone other RemoteBox then you need to
    specify `basekey`, as your SESSION and MAINKEY file
    will be encrypted with this key, and other BOX_DATA with `mainkey`.
    
    Returns `db_path`.
    '''
    mkdir(path_join(db_path,'BOX_DATA'))
    mkdir(download_path)
    
    if basekey:
        with open(path_join(db_path,'BOX_DATA','MAINKEY'),'wb') as f:
            f.write(b''.join(aes_encrypt(mainkey.key, basekey)))
    
    with open(path_join(db_path,'BOX_DATA','SESSION'),'wb') as f:
        if basekey:
            f.write(b''.join(aes_encrypt(session.encode(), basekey)))
        else:
            f.write(b''.join(aes_encrypt(session.encode(), mainkey)))
    
    with open(path_join(db_path,'BOX_DATA','BOX_SALT'),'wb') as f:
        f.write(box_salt)
    
    with open(path_join(db_path,'BOX_DATA','BOX_CHANNEL_ID'),'wb') as f:
        f.write(b''.join(aes_encrypt(int_to_bytes(box_channel_id), mainkey)))

    with open(path_join(db_path,'BOX_DATA','NO_FOLDER'),'wb') as f:
        f.write(b''.join(aes_encrypt(b'NO_FOLDER', mainkey, 
            make_folder_iv(mainkey), concat_iv=False)
        ))
    with open(path_join(db_path,'BOX_DATA','BOX_CR_TIME'),'wb') as f:
        box_cr_time = box_cr_time if box_cr_time else int(time())
        f.write(b''.join(aes_encrypt(int_to_bytes(box_cr_time), mainkey)))

    with open(path_join(db_path,'BOX_DATA','LAST_FILE_ID'),'wb') as f:
        f.close()
    
    return db_path
        
def make_db_folder(foldername: str, key: Key, db_path: str=DB_PATH) -> str:
    foldername = foldername.encode() if not isinstance(foldername, bytes) else foldername
    folder_iv = make_folder_iv(key)
    
    enc_b64_fon = b64encode(b''.join(
        aes_encrypt(foldername, key, folder_iv, concat_iv=False))).decode()
    # ^ We don't concat IV to the foldernames to reduce name length.
    #   We can simply get IV that we need by making sha256 of the mainkey.
    
    folder_path = path_join(db_path, enc_b64_fon)
    mkdir(folder_path)

    with open(path_join(db_path, enc_b64_fon, 'FOLDER_CR_TIME'),'wb') as f:
        f.write(b''.join(aes_encrypt(int_to_bytes(int(time())), key)))
    
    return folder_path
    
def make_db_file_folder(
        filename: str, foldername: str, mainkey: MainKey, 
        filekey: FileKey, db_path: str=DB_PATH) -> str:

    folder_iv = make_folder_iv(mainkey)
    file_folder_iv = make_folder_iv(filekey)
    # ^ Only for foldernames. In other cases `urandom(16).`
    
    try:
        make_db_folder(foldername, mainkey, db_path)
    except FileExistsError:
        pass
    
    filename = filename.encode()
    foldername = foldername.encode()
    
    enc_b64_fin = b64encode(b''.join(aes_encrypt(filename, filekey, file_folder_iv, concat_iv=False))).decode()
    enc_b64_fon = b64encode(b''.join(aes_encrypt(foldername, mainkey, folder_iv, concat_iv=False))).decode() 
    
    file_folder_path = path_join(db_path, enc_b64_fon, enc_b64_fin)
    mkdir(file_folder_path)

    return file_folder_path

def rm_db_folder(enc_foldername: str, db_path: str=DB_PATH) -> None: # todo
    '''
    Removes folder in LocalBox encrypted filename (folder).
    Caution: **THIS WILL REMOVE ALL LocalBox FILE INFO IN THIS FOLDER**.
    You can re-download it from RemoteBox.

    Be careful with `db_path` and `enc_foldername`.
    This function removes directory `f'{db_path}/{enc_foldername}'`.
    '''
    rmtree(path_join(db_path, enc_foldername))

def rm_db_file_folder(
        enc_filename: str, enc_foldername: str,
        db_path: str=DB_PATH) -> None: # todo
    '''
    Removes file in LocalBox by encrypted filename (folder).
    Caution: **THIS WILL REMOVE ALL FILE INFO IN LocalBox**.
    You can re-download it from RemoteBox.

    Be careful with `db_path`, `enc_foldername` and `enc_filename`.
    This function removes directory `f'{db_path}/{enc_foldername}/{enc_filename}'`.
    '''
    rmtree(path_join(db_path, enc_foldername, enc_filename))

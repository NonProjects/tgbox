import random

from os import urandom
from hashlib import sha256, scrypt
from typing import Generator, Union, Optional

from base64 import (
    urlsafe_b64encode as b64encode,  # We use urlsafe base64.
    urlsafe_b64decode as b64decode
)
from ecdsa.ecdh import ECDH
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey

from .constants import (
    SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_SALT,
    SCRYPT_DKLEN, WORDS_PATH
)
from .crypto import aes_encrypt, aes_decrypt

class Phrase:
    def __init__(self, phrase: bytes):
        self._phrase = phrase
    
    def __hash__(self) -> int:
        return hash((self._key, self._key_type))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self._key == other.key,
            self._key_type == other.key_type
        ))   
    @property
    def phrase(self) -> bytes:
        return self._phrase
    
    @classmethod
    def generate(cls, length: int=12) -> 'Phrase':
        random.seed(urandom(32))
        words_list = open(WORDS_PATH, 'rb').readlines()
        phrase = [random.choice(words_list)[:-1] for _ in range(length)]     
        return cls(b' '.join(phrase))

class Key:
    def __init__(self, key: bytes, key_type: int):
        self._key = key
        self._key_type = key_type
        self._key_types = {
            1: 'BaseKey',
            2: 'MainKey',
            3: 'RequestKey',
            4: 'ShareKey',
            5: 'ImportKey',
            6: 'FileKey'
        }
    def __hash__(self) -> int:
        return hash((self._key, self._key_type))
    
    def __eq__(self, other) -> bool:
        return all((
            isinstance(other, self.__class__), 
            self._key == other.key,
            self._key_type == other.key_type
        ))
    def __repr__(self) -> str:
        return f'{self._key_types[self._key_type]}({self._key}) # at {hex(id(self))}'
    
    def __add__(self, other: bytes) -> bytes:
        return self._key + other
    
    def __len__(self) -> int:
        return len(self._key)
    
    def __getitem__(self, key) -> int:
        return self._key[key]
    
    def __iter__(self) -> Generator[int, None, None]:
        for i in self._key:
            yield i
    
    @property
    def key_types(self) -> dict:
        return self._key_types
    
    @property
    def key_type(self) -> int:
        return self._key_type
    
    @property
    def key(self) -> bytes:
        return self._key
    
    @classmethod
    def decode(cls, encoded_key: str) -> Union[
            'BaseKey','MainKey','RequestKey',
            'ShareKey','ImportKey','FileKey']:
        '''
        '''
        ekey_types = {
            'B': BaseKey,    'M': MainKey,
            'R': RequestKey, 'S': ShareKey,
            'I': ImportKey,  'F': FileKey
        }
        ekey_type = ekey_types[encoded_key[0]]
        return ekey_type(b64decode(encoded_key[1:]))
    
    def encode(self) -> str:
        prefix = self._key_types[self._key_type][0]
        return prefix + b64encode(self._key).decode()
    
    def hex(self) -> str:
        return self._key.hex()

class BaseKey(Key):
    def __init__(self, key: bytes):
        super().__init__(key, 1)    

class MainKey(Key):
    def __init__(self, key: bytes):
        super().__init__(key, 2)

class RequestKey(Key):
    def __init__(self, key: bytes):
        super().__init__(key, 3)

class ShareKey(Key):
    def __init__(self, key: bytes):
        super().__init__(key, 4)

class ImportKey(Key):
    def __init__(self, key: bytes):
        super().__init__(key, 5)

class FileKey(Key):
    def __init__(self, key: bytes):
        super().__init__(key, 6)

def make_basekey(
        phrase: [bytes, 'Phrase'], *, salt: bytes=SCRYPT_SALT,
        n: int=SCRYPT_N, r: int=SCRYPT_R, p: int=SCRYPT_P, 
        dklen: int=SCRYPT_DKLEN) -> BaseKey:
    '''
    Function for retrieving BaseKeys. Uses scrypt.
    RAM consumption is calculated by `128 * r * (n + p + 2)`.
    '''
    phrase = phrase.phrase if isinstance(phrase, Phrase) else phrase
    
    m = 128 * r * (n + p + 2)
    return BaseKey(
        scrypt(phrase, n=n, r=r, dklen=dklen, 
        p=p, salt=salt, maxmem=m)
    )
def make_mainkey(basekey: BaseKey, box_salt: bytes) -> MainKey:
    '''
    Function for retrieving mainkey.

    basekey (`bytes`): 
        Key which you recieved with scrypt
        function or any other key you want.

    box_salt (`bytes`): 
        Salt generated on LocalBox creation.
        Must be on DB_PATH/BOX_DATA/BOX_SALT.
    '''
    return MainKey(sha256(basekey + box_salt).digest())

def make_filekey(mainkey: MainKey, file_salt: bytes) -> FileKey:
    '''
    Function for retrieving filekeys.

    Every LocalBoxFile have random generated on encryption FILE_SALT.
    Key for file encryption we create as `sha256(mainkey + FILE_SALT)`.

    Thanks to this, you can share the key with which
    the file was encrypted (filekey) without revealing your mainkey.
    '''
    return FileKey(sha256(mainkey + file_salt).digest())

def make_requestkey(
        mainkey: MainKey, *, file_salt: Optional[bytes] = None, 
        box_salt: Optional[bytes] = None) -> RequestKey:
    '''
    Function to retrieve requestkeys.
    
    All files in RemoteBoxes is encrypted with filekeys, so
    if you want to share (or import) file, then you need to
    get filekey. For this purpose you can create `RequestKey`.
    
    Alice has file in her Box which she wants to send to Bob.
    Then: A sends file to B. B forwards file to his Box, takes
    `FILE_SALT` and `mainkey` of his Box and (i.e) calls
    `make_requestkey(mainkey=mainkey, file_salt=file_salt)`.
    
    RequestKeys is compressed pubkeys of ECDH on secp256k1, 
    B makes privkey with `sha256(mainkey + salt)` & exports pubkey
    to make a shared secret bytes (key, with which A will be
    encrypt her filekey or mainkey, encrypted (file/main)key 
    is called `ShareKey`. Use help on `make_sharekey`.).
    
    B sends received `RequestKey` to A. A creates `ShareKey`
    and sends to B. B calls `get_importkey` and recieves filekey.
    
    No one except Alice and Bob will have filekey. If Alice want
    to share entire Box (mainkey) with Bob, then Bob creates
    slightly different `RequestKey` with same function:
    `make_requestkey(mainkey=mainkey, box_salt=box_salt)`.
    
    To get `BOX_SALT` Alice should only add Bob to her Box(`Channel`).
    
    Functions in this module is low-level, you can make `RequestKey` for
    a forwarded from A file by calling `get_requestkey(...)` 
    method of `EncryptedRemoteBoxFile`.
    
    mainkey (`MainKey`):
        Your Box key.
    
    file_salt (`bytes`, optional):
        File Salt. Should be specified if `box_salt` is `None`.
    
    box_salt (`bytes`, optional):
        Box Salt. Should be specified if `file_salt` is `None`.
    '''
    if not any((file_salt, box_salt)):
        raise ValueError(
            'At least one of the box_salt or file_salt must be specified.'
        )
    salt = file_salt if file_salt else box_salt
    
    skey = SigningKey.from_string(
        sha256(mainkey + salt).digest(),
        curve=SECP256k1, hashfunc=sha256
    )
    vkey = skey.get_verifying_key()._compressed_encode()
    return RequestKey(vkey)

def make_sharekey(
     *, mainkey: Optional[MainKey] = None, 
        requestkey: Optional[RequestKey] = None,  
        box_salt: Optional[bytes] = None, 
        filekey: Optional[FileKey] = None,
        file_salt: Optional[bytes] = None
        ) -> Union[ShareKey, ImportKey]:
    '''
    Function for making ShareKeys.
    
    You may want to know what is `RequestKey` before reading
    this. Please, run help on `make_requestkey` to get info.
    
    Alice recieves `RequestKey` of Bob. But what should we do
    next? As reqkey is just EC-pubkey, we want to make a shared
    secret key. A makes her own privkey as B, with
    `sha256(mainkey + salt)` & initializes ECDH with B pubkey
    and her privkey. After this, A makes a shared secret, which
    is 32-byte length AES-CBC key & encrypts her file or main key. 
    IV here is first 16 byte of `sha256(requestkey)`. Then she
    prepends her pubkey to the result and sends it to Bob.
    
    With A pubkey, B can easily get the same shared secret and
    decrypt `ShareKey` to make the `ImportKey`.
    
    The things will be much less complicated if Alice don't mind
    to share her File or Box with ALL peoples. Then she drops only
    her file or main key in raw. Simple is better than complex, after all.
    
    mainkey (`MainKey`, optional):
        Your Box key. Specify only this kwarg if you want to
        share your Box with **ALL** peoples. No decryption.
    
    filekey (`FileKey`, optional):
        Your Filekey. Specify only this kwarg if you want to
        share your File with **ALL** peoples. No decryption.
    
    requestkey (`RequestKey`, optional):
        `RequestKey` of Bob. With this must be specified
        `file_salt` or `box_salt`.
    
    file_salt (`bytes`, optional):
        Salt (`FILE_SALT`) of the file. Must be specified with
        `requestkey` if `box_salt` is `None`.
    
    box_salt (`bytes`, optional):
        Box salt. Must be specified with
        `requestkey` if `file_salt` is `None`.
    '''
    if not any((requestkey, box_salt, file_salt)):
        if mainkey:
            return ImportKey(mainkey.key)
        elif filekey:
            return ImportKey(filekey.key)
        else:
            raise ValueError(
                '''Please specify at least mainkey or '''
                '''filekey, run help(make_sharekey) for help.'''
            )
    if not all((filekey, file_salt)): 
        if not box_salt:
            raise ValueError(
                '''At least one pair must be specified: '''
                '''(mainkey & box_salt) or (filekey & file_salt) '''
                '''with requestkey.'''
            )
        else:
            salt, key = box_salt, mainkey
    else:
        salt, key = file_salt, filekey
    
    skey = SigningKey.from_string(
        sha256(key + salt).digest(),
        curve=SECP256k1, hashfunc=sha256
    )
    b_point = VerifyingKey._from_compressed(
        requestkey.key, curve=SECP256k1
    )
    b_pubkey = VerifyingKey.from_public_point(
        b_point, curve=SECP256k1, hashfunc=sha256
    )
    ecdh = ECDH(
        curve=SECP256k1, 
        private_key=skey, 
        public_key=b_pubkey
    )
    enc_key = ecdh.generate_sharedsecret_bytes()
    iv = sha256(requestkey.key).digest()[:16]

    encrypted_key = b''.join(aes_encrypt(
        key.key, key=enc_key, iv=iv, 
        add_padding=False, concat_iv=False
    ))
    return ShareKey(encrypted_key +\
        skey.get_verifying_key()._compressed_encode()
    )
def make_importkey(
        mainkey: MainKey, sharekey: ShareKey, *,
        box_salt: Optional[bytes] = None, 
        file_salt: Optional[bytes] = None) -> ImportKey:
    '''
    '''
    if len(sharekey) == 32: # Key isn't encrypted.
        return ImportKey(sharekey.key) 
    else:
        if not any((box_salt, file_salt)):
            raise ValueError(
                'At least box_salt or file_salt must be specified.'
            )
        else:
            salt = box_salt if box_salt else file_salt

            requestkey = make_requestkey(
                mainkey, box_salt=box_salt, file_salt=file_salt
            )
            skey = SigningKey.from_string(
                sha256(mainkey + salt).digest(),
                curve=SECP256k1, hashfunc=sha256
            )
            a_point = VerifyingKey._from_compressed(
                sharekey[32:], curve=SECP256k1
            )
            a_pubkey = VerifyingKey.from_public_point(
                a_point, curve=SECP256k1, hashfunc=sha256
            )
            ecdh = ECDH(
                curve=SECP256k1, 
                private_key=skey, 
                public_key=a_pubkey
            )
            dec_key = ecdh.generate_sharedsecret_bytes()
            iv = sha256(requestkey.key).digest()[:16]

            decrypted_key = b''.join(aes_decrypt(
                sharekey[:32], key=dec_key, 
                iv=iv, strip_padding=False
            ))
            return ImportKey(decrypted_key)
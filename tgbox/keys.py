"""This module stores all keys and keys making functions."""

from os import urandom
from random import SystemRandom

from hashlib import sha256
try:
    from hashlib import scrypt
except ImportError:
    # This is for ReadTheDocs. Maybe TODO.
    from Crypto.Protocol.KDF import scrypt

from typing import (
    AsyncGenerator, 
    Union, Optional
)
from base64 import (
    urlsafe_b64encode,
    urlsafe_b64decode 
)
from ecdsa.ecdh import ECDH
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey

from .constants import (
    SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_SALT,
    SCRYPT_DKLEN, WORDS_PATH
)
from .crypto import aes_encrypt, aes_decrypt


__all__ = [
    'Phrase', 
    'Key', 
    'BaseKey', 
    'MainKey', 
    'RequestKey', 
    'ShareKey', 
    'ImportKey', 
    'FileKey', 
    'EncryptedMainkey', 
    'make_basekey', 
    'make_mainkey', 
    'make_filekey', 
    'make_requestkey', 
    'make_sharekey', 
    'make_importkey'
]

class Phrase:
    """This class represents passphrase"""
    def __init__(self, phrase: Union[bytes, str]):
        if isinstance(phrase, str):
            self._phrase = phrase.encode()
        else:
            self._phrase = phrase
    
    def __repr__(self) -> str:
        return f'Phrase({repr(self._phrase)}) # at {hex(id(self))}'

    def __hash__(self) -> int:
        # Without 22 hash of bytes will be equal to object's
        return hash((self._phrase,22))
    
    def __eq__(self, other) -> bool:
        return hash(self) == hash(other)

    @property
    def phrase(self) -> bytes:
        """Returns currrent raw phrase"""
        return self._phrase
    
    @classmethod
    def generate(cls, words_count: int=12) -> 'Phrase':
        """
        Generates passphrase
        
        Arguments:
            words_count (``int``, optional):
                Words count in ``Phrase``.
        """
        sysrnd = SystemRandom(urandom(32))
        words_list = open(WORDS_PATH,'rb').readlines()

        phrase = [
            sysrnd.choice(words_list)[:-1] 
            for _ in range(words_count)
        ]     
        return cls(b' '.join(phrase))

class Key:
    """Metaclass that represents all keys."""
    def __init__(self, key: bytes, key_type: int):
        """
        Arguments:
            key (``bytes``):
                Raw bytes key.

            key_type (``int``):
                Type of key, where:
                    1: ``BaseKey``
                    2: ``MainKey``
                    3: ``RequestKey``
                    4: ``ShareKey``
                    5: ``ImportKey``
                    6: ``FileKey``
                    7: ``EncryptedMainkey``
        """
        self._key = key
        self._key_type = key_type
        self._key_types = {
            1: 'BaseKey',
            2: 'MainKey',
            3: 'RequestKey',
            4: 'ShareKey',
            5: 'ImportKey',
            6: 'FileKey',
            7: 'EncryptedMainkey'
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
    
    def __iter__(self) -> AsyncGenerator[int, None]:
        for i in self._key:
            yield i
    
    @property
    def key_types(self) -> dict:
        """Returns all key types"""
        return self._key_types.copy()
    
    @property
    def key_type(self) -> int:
        """Returns current key type"""
        return self._key_type
    
    @property
    def key(self) -> bytes:
        """Returns key in raw"""
        return self._key
    
    @classmethod
    def decode(cls, encoded_key: str) -> Union[
            'BaseKey','MainKey','RequestKey',
            'ShareKey','ImportKey','FileKey',
            'EncryptedMainkey']:
        """
        Decodes Key by prefix and returns
        ``Key`` in one of ``Key`` classes.

        B: ``BaseKey``
        M: ``MainKey``
        R: ``RequestKey`` 
        S: ``ShareKey``
        I: ``ImportKey`` 
        F: ``FileKey``
        E: ``EncryptedMainkey``

        Key example:
            ``MSGVsbG8hIEkgYW0gTm9uISBJdCdzIDI5LzExLzIwMjE=``.
            You can decode it with ``Key.decode``.
        """
        ekey_types = {
            'B': BaseKey,    'M': MainKey,
            'R': RequestKey, 'S': ShareKey,
            'I': ImportKey,  'F': FileKey,
            'E': EncryptedMainkey
        }
        ekey_type = ekey_types[encoded_key[0]]
        return ekey_type(urlsafe_b64decode(encoded_key[1:]))
    
    def encode(self) -> str:
        """Encode raw key with ``urlsafe_b64encode`` and add prefix."""
        prefix = self._key_types[self._key_type][0]
        return prefix + urlsafe_b64encode(self._key).decode()
    
    def hex(self) -> str:
        """Returns key in hex represenation"""
        return self._key.hex()

class BaseKey(Key):
    """
    This ``Key`` used for ``MainKey`` creation and
    cloned ``RemoteBox`` decryption. In API
    it's usually result of ``keys.make_basekey``.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 1)    

class MainKey(Key):
    """
    ``MainKey`` may be reffered as "BoxKey". This
    key encrypts all BoxData and used in ``FileKey``
    creation. It's one of your most important ``Key``,
    as leakage of it will result in compromising all
    your encrypted files in ``RemoteBox`` & LocalBox.

    When you clone other's ``RemoteBox``, Session data
    encrypts with ``BaseKey``, not ``MainKey``.

    Usually you will see this ``Key`` as a result of
    ``keys.make_mainkey`` function.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 2)

class RequestKey(Key):
    """Run ``help(tgbox.keys.make_requestkey)`` for info."""
    def __init__(self, key: bytes):
        super().__init__(key, 3)

class ShareKey(Key):
    """Run ``help(tgbox.keys.make_sharekey)`` for info."""
    def __init__(self, key: bytes):
        super().__init__(key, 4)

class ImportKey(Key):
    """Run ``help(tgbox.keys.make_importkey)`` for info."""
    def __init__(self, key: bytes):
        super().__init__(key, 5)

class FileKey(Key):
    """
    ``FileKey`` is used for encrypting ``RemoteBox`` files
    and information about them in your LocalBox. If
    you share one ``FileKey``, other people will be able
    to decrypt only file, that key corresponds to, and
    no more. They will not be able to get folder of this
    file. Only those, who have ``MainKey`` can access 
    folder information from file's Metadata.
    
    .. note::
        Usually you will not work with this code, API
        converts ``MainKey`` to ``FileKey`` under the hood,
        but you can make it with ``keys.make_filekey``.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 6)

class EncryptedMainkey(Key):
    """
    This class represents encrypted mainkey. When
    you clone other's ``RemoteBox``, it's ``MainKey``
    encrypts with your ``BaseKey``.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 7)

def make_basekey(
        phrase: Union[bytes, Phrase], *, salt: bytes=SCRYPT_SALT,
        n: int=SCRYPT_N, r: int=SCRYPT_R, p: int=SCRYPT_P, 
        dklen: int=SCRYPT_DKLEN) -> BaseKey:
    """
    Function for retrieving BaseKeys. Uses ``sha256(scrypt(*))``.

    .. warning::
        RAM consumption is calculated by ``128 * r * (n + p + 2)``.
    
    Arguments:
        phrase (``bytes``, ``Phrase``):
            Passphrase from which 
            ``BaseKey`` will be created.

        salt (``bytes``, optional):
            Scrypt Salt.

        n (``int``, optional):
            Scrypt N.

        r (``int``, optional):
            Scrypt R.

        p (``int``, optional):
            Scrypt P.

        dklen (``int``, optional):
            Scrypt dklen.
    """
    phrase = phrase.phrase if isinstance(phrase, Phrase) else phrase
    
    m = 128 * r * (n + p + 2)
    scrypt_key = scrypt(
        phrase, n=n, r=r, 
        dklen=dklen, p=p, 
        salt=salt, maxmem=m
    )
    return BaseKey(sha256(scrypt_key).digest())

def make_mainkey(basekey: BaseKey, box_salt: bytes) -> MainKey:
    """
    Function for retrieving mainkey.
    
    Arguments:
        basekey (``bytes``): 
            Key which you recieved with scrypt
            function or any other key you want.

        box_salt (``bytes``): 
            Salt generated on LocalBox creation.
    """
    return MainKey(sha256(basekey + box_salt).digest())

def make_filekey(mainkey: MainKey, file_salt: bytes) -> FileKey:
    """
    Function for retrieving filekeys.

    Every LocalBoxFile have random generated on encryption FileSalt.
    Key for file encryption we create as ``sha256(mainkey + FileSalt)``.

    Thanks to this, you can share the key with which
    the file was encrypted (filekey) without revealing your mainkey.
    """
    return FileKey(sha256(mainkey + file_salt).digest())

def make_requestkey(
        mainkey: MainKey, *, file_salt: Optional[bytes] = None, 
        box_salt: Optional[bytes] = None) -> RequestKey:
    """
    Function to retrieve requestkeys.
    
    All files in RemoteBoxes is encrypted with filekeys, so
    if you want to share (or import) file, then you need to
    get filekey. For this purpose you can create ``RequestKey``.
    
    Alice has file in her Box which she wants to send to Bob.
    Then: A sends file to B. B forwards file to his Box, takes
    FileSalt from A File and ``mainkey`` of his Box and (i.e) calls
    ``make_requestkey(mainkey=mainkey, file_salt=file_salt)``.
    
    RequestKeys is compressed pubkeys of ECDH on secp256k1, 
    B makes privkey with ``sha256(mainkey + salt)`` & exports pubkey
    to make a shared secret bytes (key, with which A will be
    encrypt her filekey/mainkey, encrypted (file/main)key 
    is called ``ShareKey``. Use help on ``make_sharekey``.).
    
    B sends received ``RequestKey`` to A. A makes ``ShareKey``
    and sends it to B. B calls ``get_importkey`` and recieves filekey.
    
    No one except Alice and Bob will have filekey. If Alice want
    to share entire Box (mainkey) with Bob, then Bob creates
    slightly different ``RequestKey`` with same function:
    ``make_requestkey(mainkey=mainkey, box_salt=box_salt)``.
    
    To get BoxSalt Alice should only add Bob to her Box(``Channel``).
    
    .. note::
        Functions in this module is low-level, you can make ``RequestKey`` for
        a forwarded from A file by calling ``get_requestkey(...)`` 
        method on ``EncryptedRemoteBoxFile``.

    Arguments:
        mainkey (``MainKey``):
            Bob's ``MainKey``. 
        
        file_salt (``bytes``, optional):
            Alice's FileSalt. 
            Should be specified if ``box_salt`` is ``None``.
        
        box_salt (``bytes``, optional):
            Alice's BoxSalt. 
            Should be specified if ``file_salt`` is ``None``.
    """
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
    """
    Function for making ShareKeys.
    
    .. note::
        You may want to know what is ``RequestKey`` before reading
        this. Please, run help on ``make_requestkey`` to get info.
    
    Alice recieves ``RequestKey`` from Bob. But what she should do
    next? As reqkey is just EC-pubkey, she wants to make a shared
    secret key. A makes her own privkey as B, with
    ``sha256(mainkey + salt)`` & initializes ECDH with B pubkey
    and her privkey. After this, A makes a shared secret, which
    is 32-byte length AES-CBC key & encrypts her file/main key. 
    IV here is first 16 byte of ``sha256(requestkey)``. Then she
    prepends her pubkey to the result and sends it to Bob.
    
    With A pubkey, B can easily get the same shared secret and
    decrypt ``ShareKey`` to make the ``ImportKey``.
    
    The things will be much less complicated if Alice don't mind
    to share her File or Box with ALL peoples. Then she drops only
    her file or main key in raw. Simple is better than complex, after all.
    
    Arguments:
        mainkey (``MainKey``, optional):
            Your Box key. Specify only this kwarg if you want to
            share your Box with **ALL** peoples. No decryption.
        
        filekey (``FileKey``, optional):
            Your Filekey. Specify only this kwarg if you want to
            share your File with **ALL** peoples. No decryption.
        
        requestkey (``RequestKey``, optional):
            ``RequestKey`` of Bob. With this must be specified
            ``file_salt`` or ``box_salt``.
        
        file_salt (``bytes``, optional):
            Salt (``FILE_SALT``) of the file. Must be specified with
            ``requestkey`` if ``box_salt`` is ``None``.
        
        box_salt (``bytes``, optional):
            Box salt. Must be specified with
            ``requestkey`` if ``file_salt`` is ``None``.
    """
    if not any((requestkey, box_salt, file_salt)):
        if mainkey:
            return ImportKey(mainkey.key)
        elif filekey:
            return ImportKey(filekey.key)
        else:
            raise ValueError(
                """Please specify at least mainkey or """
                """filekey, run help(make_sharekey) for help."""
            )
    if not all((filekey, file_salt)): 
        if not box_salt:
            raise ValueError(
                """At least one pair must be specified: """
                """(mainkey & box_salt) or (filekey & file_salt) """
                """with requestkey."""
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
    """
    .. note::
        You may want to know what is ``RequestKey`` and 
        ``ShareKey`` before using this. Use ``help()`` on
        another ``make_*key`` functions.
    
    ``ShareKey`` is a combination of encrypted by Alice
    (File/Main)Key and her pubkey. As Bob can create
    again ``RequestKey``, which is PubKey of ECDH from
    ``sha256(mainkey + salt)`` PrivKey, and already have
    PubKey of A, -- B can create a shared secret, and
    decrypt A ``ShareKey`` to make an ``ImportKey``.
    
    Arguments:
        mainkey (``MainKey``):
            ``MainKey`` that was used 
            in ``RequestKey`` creation.

        sharekey (``ShareKey``):
            Alice's ``ShareKey``.

        box_salt (``bytes``, optional):
            BoxSalt that was used in
            ``RequestKey`` creation. 

        file_salt (``bytes``, optional):
            FileSalt that was used in
            ``RequestKey`` creation. 
    
    .. note::
        At least ``box_salt`` or ``file_salt`` must
        be specified in function.
    """
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

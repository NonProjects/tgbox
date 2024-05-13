"""This module stores all keys and key making functions."""

from hmac import HMAC
from os import urandom
from random import SystemRandom

from typing import (
    AsyncGenerator,
    Union, Optional
)
from base64 import (
    urlsafe_b64encode,
    urlsafe_b64decode
)
from .errors import IncorrectKey
from .defaults import Scrypt, WORDS_PATH, READTHEDOCS

from .crypto import (
    AESwState as AES, FAST_ENCRYPTION,
    Salt, BoxSalt, FileSalt)
try:
    from hashlib import sha256, scrypt
except ImportError: # No Scrypt installed
    if FAST_ENCRYPTION:
        from cryptography.hazmat.primitives.kdf.scrypt\
            import Scrypt as cryptography_Scrypt

        def scrypt(
                password: bytes, *, salt=None, n=None,
                r=None, p=None, maxmem=0, dklen=64): # pylint: disable=unused-argument
            """
            This is a little wrapper around the Scrypt
            from the cryptography library.
            """
            s = cryptography_Scrypt(salt=salt, length=dklen, n=n, r=r, p=p)
            return s.derive(password)
    else:
        if not READTHEDOCS: # ReadTheDocs does not have Scrypt in hashlib
            raise RuntimeError('Could not find Scrypt. Install tgbox[fast]')

if FAST_ENCRYPTION: # Is faster and more secure
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import PublicFormat
    from cryptography.hazmat.primitives.serialization import Encoding
else:
    from ecdsa.ecdh import ECDH
    from ecdsa.curves import SECP256k1
    from ecdsa.keys import SigningKey, VerifyingKey

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
    'DirectoryKey',
    'HMACKey',

    'make_basekey',
    'make_mainkey',
    'make_filekey',
    'make_requestkey',
    'make_sharekey',
    'make_importkey',
    'make_dirkey',
    'make_hmackey'
]

class Phrase:
    """This class represents passphrase"""
    def __init__(self, phrase: Union[bytes, str]):
        if isinstance(phrase, str):
            self._phrase = phrase.encode()

        elif isinstance(phrase, bytes):
            self._phrase = phrase
        else:
            raise TypeError('phrase must be Union[bytes, str]')

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f'{class_name}({repr(self._phrase)}) # at {hex(id(self))}'

    def __str__(self) -> str:
        return self._phrase.decode()

    def __hash__(self) -> int:
        # Without 22 hash of bytes will be equal to object's
        return hash((self._phrase,22))

    def __eq__(self, other) -> bool:
        return hash(self) == hash(other)

    @property
    def phrase(self) -> bytes:
        """Returns current raw phrase"""
        return self._phrase

    @classmethod
    def generate(cls, words_count: int=6) -> 'Phrase':
        """
        Generates passphrase

        Arguments:
            words_count (``int``, optional):
                Words count in ``Phrase``.
        """
        sysrnd = SystemRandom(urandom(32))

        with open(WORDS_PATH,'rb') as words_file:
            words_list = words_file.readlines()

            phrase = [
                sysrnd.choice(words_list).strip()
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
                    8: ``DirectoryKey``
                    9: ``HMACKey``
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
            7: 'EncryptedMainkey',
            8: 'DirectoryKey',
            9: 'HMACKey'
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

    def __add__(self, other) -> bytes:
        if isinstance(other, Salt):
            return self._key + other.salt
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
            'EncryptedMainkey', 'DirectoryKey',
            'HMACKey']:
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
        D: ``DirectoryKey``
        H: ``HMACKey``

        Key example:
            ``MSGVsbG8hIEkgYW0gTm9uISBJdCdzIDI5LzExLzIwMjE=``.
            You can decode it with ``Key.decode``.
        """
        try:
            ekey_types = {
                'B': BaseKey,    'M': MainKey,
                'R': RequestKey, 'S': ShareKey,
                'I': ImportKey,  'F': FileKey,

                'E': EncryptedMainkey,
                'D': DirectoryKey,
                'H': HMACKey
            }
            ekey_type = ekey_types[encoded_key[0]]
            return ekey_type(urlsafe_b64decode(encoded_key[1:]))
        except:
            raise IncorrectKey(IncorrectKey.__doc__)

    def encode(self) -> str:
        """Encode raw key with ``urlsafe_b64encode`` and add prefix."""
        prefix = self._key_types[self._key_type][0]
        return prefix + urlsafe_b64encode(self._key).decode()

    def hex(self) -> str:
        """Returns key in hex representation"""
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
    ``MainKey`` may be referred as "Box key". This
    key encrypts all box data and used in ``FileKey``
    creation. It's one of your most important ``Key``,
    as leakage of it will result in compromising all
    your encrypted files in *RemoteBox* & *LocalBox*.

    When you clone other's *RemoteBox*, Session data
    will be encrypted by ``BaseKey``, not ``MainKey``.

    Usually you will see this ``Key`` as a result of
    ``keys.make_mainkey`` function.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 2)

class RequestKey(Key):
    """
    The ``RequestKey`` is a key that *Requester*
    creates when [s]he wants to import *Giver's*
    file, directory or even clone other's
    *RemoteBox* and access all files.

    With ``RequestKey`` *Giver* makes ``ShareKey``.
    Run ``help(tgbox.keys.make_requestkey)`` for information.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 3)

class ShareKey(Key):
    """
    The ``ShareKey`` is a key that *Giver* creates
    when [s]he wants to share file, directory or
    even the whole *Box* with the *Requester*.

    With ``ShareKey`` *Requester* makes ``ImportKey``.
    Run ``help(tgbox.keys.make_sharekey)`` for information.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 4)

class ImportKey(Key):
    """
    The ``ImportKey`` is a key that *Requester*
    obtains after calling ``make_importkey``
    function with the ``ShareKey``. This is
    a decryption key for the requested object.

    Run ``help(tgbox.keys.make_importkey)`` for information.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 5)

class FileKey(Key):
    """
    ``FileKey`` is a key that used for encrypting
    file's bytedata and its metadata on upload. The
    ``FileKey`` encrypts all of *secret metadata* values
    except the ``efile_path`` (encrypted file path), so
    user with which you share file from your *Box*
    will not know from which directory it was extracted.

    .. note::
        Usually you will not work with this class, API
        converts ``DirectoryKey`` to ``FileKey`` under the hood,
        but you can make it with ``tgbox.keys.make_filekey``.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 6)

class EncryptedMainkey(Key):
    """
    This class represents encrypted mainkey. When
    you clone other's *RemoteBox* we encrypt its
    ``MainKey`` with your ``BaseKey``.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 7)

class DirectoryKey(Key):
    """
    ``DirectoryKey`` is a ``Key`` that was added in the
    ``v1.3``. In previous versions, ``FileKey`` was
    generated with the *SHA256* over the ``MainKey``
    and ``FileSalt``. Now we will make it with the
    ``DirectoryKey``. See Docs for more information.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 8)

class HMACKey(Key):
    """
    ``HMACKey`` is a ``Key`` that is used to make a
    *HMAC* of the bytestring. Typically, ``HMACKey``
    is a result of a ``tgbox.keys.make_hmackey`` func.
    """
    def __init__(self, key: bytes):
        super().__init__(key, 9)

def make_basekey(
        phrase: Union[bytes, Phrase],
        *,
        salt: Union[bytes, int] = Scrypt.SALT,
        n: Optional[int] = Scrypt.N,
        r: Optional[int] = Scrypt.R,
        p: Optional[int] = Scrypt.P,
        dklen: Optional[int] = Scrypt.DKLEN) -> BaseKey:
    """
    Function to create ``BaseKey``.
    Uses the ``sha256(scrypt(...))``.

    .. warning::
        RAM consumption is calculated by ``128 * r * (n + p + 2)``.

    Arguments:
        phrase (``bytes``, ``Phrase``):
            Passphrase from which
            ``BaseKey`` will be created.

        salt (``bytes``, ``int``, optional):
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

    if isinstance(salt, int):
        bit_length = ((salt.bit_length() + 8) // 8)
        length = (bit_length * 8 ) // 8

        salt = int.to_bytes(salt, length, 'big')

    maxmem = 128 * r * (n + p + 2)
    scrypt_key = scrypt(
        phrase, n=n, r=r, dklen=dklen,
        p=p, salt=salt, maxmem=maxmem
    )
    return BaseKey(sha256(scrypt_key).digest())

def make_mainkey(basekey: BaseKey, box_salt: BoxSalt) -> MainKey:
    """
    Function to create ``MainKey``.

    Arguments:
        basekey (``bytes``):
            Key which you received with scrypt
            function or any other key you want.

        box_salt (``BoxSalt``):
            ``BoxSalt`` generated on *LocalBox* creation.
    """
    return MainKey(sha256(basekey + box_salt).digest())

def make_filekey(key: Union[MainKey, DirectoryKey], file_salt: FileSalt) -> FileKey:
    """
    Function to create ``FileKey``.

    The ``FileKey`` is a ``Key`` that we use to encrypt the file
    and its metadata (except ``efile_path``) on upload. Prior to
    the version **1.3** to make a ``FileKey`` we used ``MainKey``
    and the ``FileSalt``, which is randomly generated (on file
    preparation) 32 bytes. Started from now, instead of the
    ``MainKey`` we will use the ``DirectoryKey``, but you can
    still generate old *FileKey(s)* with ``MainKey``, it's
    here only for backward compatibility and this is legacy.

    ``MainKey`` or ``DirectoryKey`` *can not* be restored
    from the ``FileKey``, so it's safe-to-share.

    The main benefit in using the ``DirectoryKey`` over
    ``MainKey`` is that in old versions you will need
    to share each of files from your *Box* separately,
    while now you can share the one ``DirectoryKey``
    and *Requester* will be able to make all of the
    *FileKeys* to range of files in Dir by himself.

    You still can share files separately, though.

    See docs if you want to learn more about the
    *Keys hierarchy* structure & other things.

    Arguments:
        key (``MainKey`` (legacy), ``DirectoryKey``):
            Key which will be used to make a ``FileKey``.

        file_salt (``FileSalt``):
            ``FileSalt`` generated on file prepare.
    """
    return FileKey(sha256(key + file_salt).digest())

def make_hmackey(filekey: FileKey, file_salt: FileSalt) -> HMACKey:
    """
    Function to create ``HMACKey``.

    ``HMACKey`` is a ``Key`` that is used exclusively
    to derive a *HMAC* (by default *SHA256*) of a
    *File* or any target bytestring.

    Arguments:
        filekey (``FileKey``):
            ``FileKey`` which will be used to make a ``HMACKey``.

        file_salt (``FileSalt``):
            ``FileSalt`` that correspond to ``FileKey``.
    """
    return HMACKey(HMAC(filekey.key, file_salt.salt, 'sha256').digest())

def make_dirkey(mainkey: MainKey, part_id: bytes) -> DirectoryKey:
    """
    Function to create ``DirectoryKey``.

    ``DirectoryKey`` is generated from the unique
    path *PartID* and the ``MainKey``. We use the
    ``DirectoryKey`` to make a ``FileKey``. See
    ``help(tgbox.keys.DirectoryKey)`` and docs
    for more information about this type of ``Key``.
    """
    sha256_mainkey = sha256(mainkey.key).digest()
    return DirectoryKey(sha256(sha256_mainkey + part_id).digest())

def make_requestkey(key: Union[MainKey, BaseKey],
        salt: Union[FileSalt, BoxSalt, bytes]) -> RequestKey:
    """
    Function to create ``RequestKey``.

    All files in *RemoteBox* is encrypted with filekeys, so
    if you want to share (or import) file, then you need to
    get ``FileKey``. For this purpose you can create ``RequestKey``.

    Alice has file in her Box which she wants to share with Bob.
    Then: A sends file to B. B forwards file to his Box, takes
    ``FileSalt`` from A File and ``MainKey`` of his Box and calls
    ``make_requestkey(key=mainkey, salt=file_salt)``.

    ``RequestKey`` is a compressed pubkey of ECDH on *SECP256K1* curve,
    B makes privkey with ``sha256(mainkey + salt)`` & exports pubkey
    to make a shared secret bytes (key, with which A will
    encrypt her filekey/mainkey. The encrypted (file/main)key
    is called ``ShareKey``. Use help on ``make_sharekey``.).

    B sends received ``RequestKey`` to A. A makes ``ShareKey``
    and sends it to B. B calls ``get_importkey`` and receives the
    ``ImportKey``, which is, in fact, a ``FileKey``.

    No one except Alice and Bob will have ``FileKey``. If Alice want
    to share entire Box (``MainKey``) with Bob, then Bob creates
    slightly different ``RequestKey`` with same function:
    ``make_requestkey(key=mainkey, salt=box_salt)``.

    Please note that ``FileKey`` can only decrypt a some
    *RemoteBox* with which it is associated. However, if
    Alice will want to share the entire *Directory* of
    her *Box* files (i.e */home/alice/Pictures* folder)
    then Bob can make a ``RequestKey`` to any file
    from this *Directory*, and Alice will make a
    ``ShareKey`` with a ``DirectoryKey`` instead
    of ``FileKey``. See help on ``make_sharekey``.

    .. note::
        Functions in this module is low-level, you can make ``RequestKey`` for
        a forwarded from A file by calling ``get_requestkey(...)``
        method on ``EncryptedRemoteBoxFile`` | ``EncryptedRemoteBox``.

    Arguments:
        key (``MainKey``, ``BaseKey``):
            Bob's *Key*. If you want to import other's
            *file*, then you need to specify here
            ``MainKey`` of your *LocalBox*, otherwise
            specify ``BaseKey`` (to clone *RemoteBox*)

        salt (``FileSalt``, ``BoxSalt``, ``bytes``):
            Most obvious ``salt`` is Alice's ``BoxSalt`` or
            ``FileSalt``, however, ``salt`` here is just
            some bytestring that will be hashed with the
            ``MainKey`` to make the output ECDH keys
            unique, so you can specify here any bytes
            value if you understand consequences (you
            will need to re-use it on ``make_importkey``).
    """
    if not any((isinstance(salt, Salt), isinstance(salt, bytes))):
        raise ValueError('`salt` is not Union[Salt, bytes]')

    if FAST_ENCRYPTION:
        skey_data = int.from_bytes(sha256(key + salt).digest(), 'big')
        skey = ec.derive_private_key(skey_data, ec.SECP256K1())

        vkey = skey.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.CompressedPoint)
    else:
        skey = SigningKey.from_string(
            sha256(key + salt).digest(),
            curve=SECP256k1, hashfunc=sha256
        )
        vkey = skey.get_verifying_key()
        vkey = vkey.to_string('compressed')

    return RequestKey(vkey)

def make_sharekey(
    key: Union[FileKey, MainKey, DirectoryKey],
    salt: Optional[Union[FileSalt, BoxSalt, bytes]] = None,
    requestkey: Optional[RequestKey] = None) \
        -> Union[ShareKey, ImportKey]:
    """
    Function to create ``ShareKey``.

    .. note::
        You may want to know what is ``RequestKey`` before reading
        this. Please, run help on ``make_requestkey`` to get info.

    Alice received ``RequestKey`` from Bob. But what she should do
    next? As reqkey is just EC-pubkey, she wants to make a *shared
    secret key*. A makes her own privkey, with ``sha256(mainkey
    + sha256(salt + requestkey))`` & initializes ECDH with B pubkey
    and her privkey. After this, A makes a hashed with SHA256
    *shared secret*, which will be used as 32-byte length AES-CBC
    key & encrypts her *File|Main|Directory* key. IV here is first 16
    bytes of the ``sha256(requestkey)``. After, she prepends her pubkey to
    the resulted encrypted *File|Main|Directory* key and sends it to Bob.

    With A pubkey, B can easily get the same shared secret and
    decrypt ``ShareKey`` to make the ``ImportKey``.

    The things will be much less complicated if Alice don't mind
    to share her File, Dir or Box with ALL peoples. In this case
    we don't even need to make a ``ShareKey``, ``ImportKey``
    will be returned from the raw target ``Key``.

    Arguments:
        key (``MainKey``, ``FileKey``, ``DirectoryKey``):
            o If ``key`` is instance of ``MainKey``: Box key.
            Specify only this kwarg and ignore ``requestkey``
            if you want to share your Box with **ALL** peoples.
            Your Box ``key`` -- ``MainKey`` will be NOT encrypted.

            o If ``key`` is instance of ``FileKey``: File key.
            Specify only this kwarg if you want to share your
            File with **ALL** peoples. **No encryption** if
            ``RequestKey`` (as ``requestkey``) is not specified.

            o If ``key`` is instance of ``DirectoryKey``: Dir key.
            Specify only this kwarg if you want to share your
            File with **ALL** peoples. **No encryption** if
            ``RequestKey`` (as ``requestkey``) is not specified.

        salt (``FileSalt``, ``BoxSalt``, ``bytes``, optional):
            Most obvious ``salt`` is Alice's ``BoxSalt`` or
            ``FileSalt``, however, ``salt`` here is just
            some bytestring that will be hashed with the
            ``MainKey`` to make the output ECDH keys
            unique, so you can specify here any bytes
            value if you understand consequences. For
            example, we will use PartID (``bytes``) as
            salt on ``DirectoryKey`` sharing.

        requestkey (``RequestKey``, optional):
            ``RequestKey`` of Bob. With this must be
            specified ``salt``.
    """
    if not all((requestkey, salt)):
        return ImportKey(key.key)

    skey_salt = sha256(salt + requestkey.key).digest()

    if FAST_ENCRYPTION:
        skey_data = int.from_bytes(sha256(key + skey_salt).digest(), 'big')
        skey = ec.derive_private_key(skey_data, ec.SECP256K1())

        vkey = skey.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.CompressedPoint
        )
        b_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            curve=ec.SECP256K1(),
            data=requestkey.key
        )
        enc_key = skey.exchange(
            algorithm=ec.ECDH(),
            peer_public_key=b_pubkey)
    else:
        skey = SigningKey.from_string(
            sha256(key + skey_salt).digest(),
            curve=SECP256k1, hashfunc=sha256
        )
        vkey = skey.get_verifying_key()
        vkey = vkey.to_string('compressed')

        b_pubkey = VerifyingKey.from_string(
            requestkey.key, curve=SECP256k1
        )
        ecdh = ECDH(
            curve=SECP256k1,
            private_key=skey,
            public_key=b_pubkey
        )
        enc_key = ecdh.generate_sharedsecret_bytes()

    enc_key = sha256(enc_key).digest()
    iv = sha256(requestkey.key).digest()[:16]

    encrypted_key = AES(enc_key, iv).encrypt(
        key.key, pad=False, concat_iv=False
    )
    return ShareKey(encrypted_key + vkey)

def make_importkey(
        key: Union[MainKey, BaseKey], sharekey: ShareKey,
        salt: Optional[Union[FileSalt, BoxSalt, bytes]] = None) -> ImportKey:
    """
    .. note::
        You may want to know what is ``RequestKey`` and
        ``ShareKey`` before using this. Use ``help()`` on
        another ``Key`` *make* functions.

    ``ShareKey`` is a combination of encrypted by Alice
    (File/Main/Directory)Key and her pubkey. As Bob can create
    again ``RequestKey``, which is PubKey of ECDH from
    ``sha256(key + salt)`` PrivKey, and already have
    PubKey of A, -- B can create a shared secret, and
    decrypt A ``ShareKey`` to make an ``ImportKey``.

    Arguments:
        key (``MainKey``, ``BaseKey``):
            Bob's ``MainKey`` or ``BaseKey`` that
            was used on ``RequestKey`` creation.

        sharekey (``ShareKey``):
            Alice's ``ShareKey``.

        salt (``FileSalt``, ``BoxSalt``, ``bytes``, optional):
            Salt that was used on ``RequestKey`` creation.
    """
    if len(sharekey) == 32: # Key isn't encrypted.
        return ImportKey(sharekey.key)

    if not salt:
        raise ValueError('`salt` must be specified.')

    requestkey = make_requestkey(key, salt)

    if FAST_ENCRYPTION:
        skey_data = int.from_bytes(sha256(key + salt).digest(), 'big')
        skey = ec.derive_private_key(skey_data, ec.SECP256K1())

        a_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(
            curve=ec.SECP256K1(),
            data=sharekey[32:]
        )
        dec_key = skey.exchange(
            algorithm=ec.ECDH(),
            peer_public_key=a_pubkey)
    else:
        skey = SigningKey.from_string(
            sha256(key + salt).digest(),
            curve=SECP256k1, hashfunc=sha256
        )
        a_pubkey = VerifyingKey.from_string(
            sharekey[32:], curve=SECP256k1
        )
        ecdh = ECDH(
            curve=SECP256k1,
            private_key=skey,
            public_key=a_pubkey
        )
        dec_key = ecdh.generate_sharedsecret_bytes()

    dec_key = sha256(dec_key).digest()
    iv = sha256(requestkey.key).digest()[:16]

    decrypted_key = AES(dec_key, iv).decrypt(
        sharekey[:32], unpad=False
    )
    return ImportKey(decrypted_key)

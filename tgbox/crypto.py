"""This module stores all cryptography used in API."""

import logging

logger = logging.getLogger(__name__)

from os import urandom
from typing import Union, Optional

from pyaes.util import (
    append_PKCS7_padding,
    strip_PKCS7_padding
)
from .errors import ModeInvalid
try:
    from cryptography.hazmat.primitives.ciphers\
        import Cipher, algorithms, modes
    FAST_ENCRYPTION = True
    logger.info('Fast cryptography library was found.')
except ModuleNotFoundError:
    # We can use PyAES if there is no cryptography library.
    # PyAES is much slower. You can use it for quick tests.
    from pyaes import AESModeOfOperationCBC
    FAST_ENCRYPTION = False
    logger.warning('Fast cryptography library was NOT found. ')
try:
    # Check if cryptg is installed.
    from cryptg import __name__ as _
    del _
    FAST_TELETHON = True
except ModuleNotFoundError:
    FAST_TELETHON = False

__all__ = [
    'AESwState',
    'get_rnd_bytes',
    'FAST_TELETHON',
    'FAST_ENCRYPTION',
    'Salt', 'BoxSalt',
    'FileSalt', 'IV'
]
class IV:
    """This is a class-wrapper for AES IV"""
    def __init__(self, iv: Union[bytes, memoryview]):
        self.iv = iv if isinstance(iv, bytes) else bytes(iv)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({repr(self.iv)})'

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({repr(self.iv)}) # at {hex(id(self))}'

    def __add__(self, other):
        return self.iv + other

    def __len__(self) -> int:
        return len(self.iv)

    def __eq__(self, other) -> bool:
        if hasattr(other, 'iv'):
            return self.iv == other.iv
        return False

    @classmethod
    def generate(cls, bytelength: Optional[int] = 16):
        """
        Generates AES IV by ``bytelength``

        Arguments:
            bytelength (``int``, optional):
                Bytelength of IV. 16 bytes by default.
        """
        return cls(get_rnd_bytes(bytelength))

    def hex(self) -> str:
        """Returns IV as hexadecimal"""
        return self.iv.hex()

class Salt:
    """This is a class-wrapper for some TGBOX salt"""
    def __init__(self, salt: Union[bytes, memoryview]):
        self.salt = salt if isinstance(salt, bytes) else bytes(salt)

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({repr(self.salt)})'

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({repr(self.salt)}) # at {hex(id(self))}'

    def __add__(self, other):
        return self.salt + other

    def __len__(self) -> int:
        return len(self.salt)

    def __eq__(self, other) -> bool:
        if hasattr(other, 'salt'):
            return self.salt == other.salt
        return False

    @classmethod
    def generate(cls, bytelength: Optional[int] = 32):
        """
        Generates Salt by ``bytelength``

        Arguments:
            bytelength (``int``, optional):
                Bytelength of Salt. 32 bytes by default.
        """
        return cls(get_rnd_bytes(bytelength))

    def hex(self) -> str:
        """Returns Salt as hexadecimal"""
        return self.salt.hex()

class BoxSalt(Salt):
    """This is a class-wrapper for BoxSalt"""

class FileSalt(Salt):
    """This is a class-wrapper for FileSalt"""


class _PyaesState:
    def __init__(self, key: Union[bytes, 'Key'], iv: IV):
        """
        Class to wrap ``pyaes.AESModeOfOperationCBC``
        if there is no ``FAST_ENCRYPTION``.

        .. note::
            You should use only ``encrypt()`` or
            ``decrypt()`` method per one object.

        Arguments:
            key (``bytes``, ``Key``):
                AES encryption/decryption Key.

            iv (``IV``):
                AES Initialization Vector.
        """
        key = key.key if hasattr(key, 'key') else key
        self.iv = iv

        self._aes_state = AESModeOfOperationCBC( # pylint: disable=E0601
            key = bytes(key),
            iv = self.iv.iv
        )
        self.__mode = None # encrypt mode is 1 and decrypt is 2

    @staticmethod
    def __convert_memoryview(data: Union[bytes, memoryview]) -> bytes:
        # PyAES doesn't support memoryview, convert to bytes
        if isinstance(data, memoryview) and not FAST_ENCRYPTION:
            data = data.tobytes()
        return data

    def encrypt(self, data: Union[bytes, memoryview]) -> bytes:
        """``data`` length must be divisible by 16."""
        if not self.__mode:
            self.__mode = 1
        else:
            if self.__mode != 1:
                raise ModeInvalid('You should use only decrypt function.')

        data = self.__convert_memoryview(data)
        assert not len(data) % 16; total = b''

        for _ in range(len(data) // 16):
            total += self._aes_state.encrypt(data[:16])
            data = data[16:]

        return total

    def decrypt(self, data: Union[bytes, memoryview]) -> bytes:
        """``data`` length must be divisible by 16."""
        if not self.__mode:
            self.__mode = 2
        else:
            if self.__mode != 2:
                raise ModeInvalid('You should use only encrypt function.')

        data = self.__convert_memoryview(data)
        assert not len(data) % 16; total = b''

        for _ in range(len(data) // 16):
            total += self._aes_state.decrypt(data[:16])
            data = data[16:]

        return total

class AESwState:
    """
    Wrapper around AES CBC which preserve state.

    .. note::
        You should use only ``encrypt()`` or
        ``decrypt()`` method per one object.
    """
    def __init__(
            self, key: Union[bytes, 'Key'],
            iv: Optional[Union[IV, bytes]] = None
        ):
        """
        Arguments:
            key (``bytes``, ``Key``):
                AES encryption/decryption Key.

            iv (``IV``, ``bytes``, optional):
                AES Initialization Vector.

                If mode is *Encryption*, and
                isn't specified, will be used
                bytes from `urandom(16)`.

                If mode is *Decryption*, and
                isn't specified, will be used
                first 16 bytes of ciphertext.
        """
        self.key = key.key if hasattr(key, 'key') else key
        self.iv, self.__mode, self._aes_cbc = iv, None, None

        if self.iv and not isinstance(self.iv, IV):
            self.iv = IV(self.iv)
        self.__iv_concated = False

    def __repr__(self) -> str:
        return f'<class {self.__class__.__name__}(<key>, {repr(self.iv)})>'

    def __str__(self) -> str:
        return f'<class {self.__class__.__name__}(<key>, {repr(self.iv)})> # {self.__mode=}'

    def __init_aes_state(self, mode: int) -> None:
        if FAST_ENCRYPTION:
            self._aes_cbc = Cipher(algorithms.AES(self.key), modes.CBC(self.iv.iv))

            if mode == 1: # Encryption
                self._aes_cbc = self._aes_cbc.encryptor()
                setattr(self._aes_cbc, 'encrypt', self._aes_cbc.update)
            else: # Decryption
                self._aes_cbc = self._aes_cbc.decryptor()
                setattr(self._aes_cbc, 'decrypt', self._aes_cbc.update)
        else:
            self._aes_cbc = _PyaesState(self.key, self.iv)

    @property
    def mode(self) -> int:
        """
        Returns ``1`` if mode is encryption
        and ``2`` if decryption.
        """
        return self.__mode

    def encrypt(self, data: bytes, pad: bool=True, concat_iv: bool=True) -> bytes:
        """
        Encrypts ``data`` with AES CBC.

        If ``concat_iv`` is ``True``, then
        first 16 bytes of result will be IV.
        """
        if not self.__mode:
            self.__mode = 1

            if not self.iv: self.iv = IV.generate()
            self.__init_aes_state(self.__mode)
        else:
            if self.__mode != 1:
                raise ModeInvalid('You should use only decrypt method.')

        if pad: data = append_PKCS7_padding(data)
        data = self._aes_cbc.encrypt(data)

        if concat_iv and not self.__iv_concated:
            self.__iv_concated = True
            return self.iv.iv + data

        return data

    def decrypt(self, data: bytes, unpad: bool=True) -> bytes:
        """
        Decrypts ``data`` with AES CBC.

        ``data`` length must be evenly divisible by 16.
        """
        if not self.__mode:
            self.__mode = 2

            if not self.iv:
                self.iv, data = IV(data[:16]), data[16:]
            self.__init_aes_state(self.__mode)
        else:
            if self.__mode != 2:
                raise ModeInvalid('You should use only encrypt method.')

        data = self._aes_cbc.decrypt(data)
        if unpad: data = strip_PKCS7_padding(data)
        return data

def get_rnd_bytes(length: int=32) -> bytes:
    """Returns ``os.urandom(length)``."""
    return urandom(length)

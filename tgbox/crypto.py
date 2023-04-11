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
    'FAST_ENCRYPTION'
]
class _PyaesState:
    def __init__(self, key: Union[bytes, 'Key'], iv: Union[bytes, memoryview]):
        """
        Class to wrap ``pyaes.AESModeOfOperationCBC``
        if there is no ``FAST_ENCRYPTION``.

        .. note::
            You should use only ``encrypt()`` or
            ``decrypt()`` method per one object.

        Arguments:
            key (``bytes``, ``Key``):
                AES encryption/decryption Key.

            iv (``bytes``):
                AES Initialization Vector.
        """
        key = key.key if hasattr(key, 'key') else key

        self._aes_state = AESModeOfOperationCBC( # pylint: disable=E0601
            key = bytes(key), iv = bytes(iv)
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
    def __init__(
            self, key: Union[bytes, 'Key'],
            iv: Optional[bytes] = None
        ):
        """
        Wrap around AES CBC which saves state.

        .. note::
            You should use only ``encrypt()`` or
            ``decrypt()`` method per one object.

        Arguments:
            key (``bytes``, ``Key``):
                AES encryption/decryption Key.

            iv (``bytes``, optional):
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
        self.__iv_concated = False

    def __init_aes_state(self, mode: int) -> None:
        if FAST_ENCRYPTION:
            self._aes_cbc = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))

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

            if not self.iv: self.iv = urandom(16)
            self.__init_aes_state(self.__mode)
        else:
            if self.__mode != 1:
                raise ModeInvalid('You should use only decrypt method.')

        if pad: data = append_PKCS7_padding(data)
        data = self._aes_cbc.encrypt(data)

        if concat_iv and not self.__iv_concated:
            self.__iv_concated = True
            return self.iv + data

        return data

    def decrypt(self, data: bytes, unpad: bool=True) -> bytes:
        """
        Decrypts ``data`` with AES CBC.

        ``data`` length must must
        be evenly divisible by 16.
        """
        if not self.__mode:
            self.__mode = 2

            if not self.iv:
                self.iv, data = data[:16], data[16:]
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

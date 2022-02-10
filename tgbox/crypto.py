"""This module stores all cryptography used in API."""

from os import urandom

from typing import (
    BinaryIO, AsyncGenerator, 
    Union, Optional, Callable
)
from .errors import ModeInvalid, AESError
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import (
        pad as pad_, unpad as unpad_
    )
    FAST_ENCRYPTION = True
except ModuleNotFoundError: 
    # We can use PyAES if there is no pycryptodome.
    # PyAES is about 30x slower in CPython than pycryptodome.
    # This is TOO slow and not so usable, but anyway.
    from pyaes.util import ( 
        append_PKCS7_padding as pad_, 
        strip_PKCS7_padding as unpad_
    )
    from pyaes import AESModeOfOperationCBC
    FAST_ENCRYPTION = False
try:
    from cryptg import _CTX_TYPEDEF # Just to verify.
    FAST_TELETHON = True
except ModuleNotFoundError:
    FAST_TELETHON = False


__all__ = [
    'Padding', 
    'AESwState', 
    'get_rnd_bytes',
    'FAST_TELETHON',
    'FAST_ENCRYPTION'
]
class Padding:
    """
    Class that implements PKCS#7 padding. If
    PyCryptodome module isn't available, will
    be used padding function from PyAES.
    """
    _pad = pad_ if not FAST_ENCRYPTION else lambda b: pad_(b,16)
    _unpad = unpad_ if not FAST_ENCRYPTION else lambda b: unpad_(b,16)
    
    @classmethod
    def pad(
            cls, bytedata: bytes, 
            pad_func: Optional[Callable[
                [bytes], bytes]] = None) -> bytes:
        """
        Pads block with PKCS#7 padding.
        
        Arguments:
            bytedata (``bytes``):
                Bytes to be padded.

            pad_func (``Callable``):
                Padding function. 
        """
        if pad_func:
            pad_, custom = pad_func, True
        else:
            pad_, custom = cls._pad, False
        
        return pad_(bytedata)
    
    @classmethod
    def unpad(
            cls, bytedata: bytes, 
            unpad_func: Optional[Callable[
                [bytes], bytes]] = None) -> bytes:
        """
        Unpads block with PKCS#7 padding.
        
        Arguments:
            bytedata (``bytes``):
                Bytes to be unpadded.

            unpad_func (``Callable``):
                Unpadding function. 
        """
        if unpad_func:
            unpad_, custom = unpad_func, True
        else:
            unpad_, custom = cls._unpad, False
        
        while True:
            try:
                bytedata = unpad_(bytedata)
            except (ValueError, IndexError): 
                return bytedata # No more padding

    @classmethod
    def cycle_pad(cls, bytedata: bytes, to_len: int, pad_func=None) -> bytes:
        """
        Pads block with PKCS#7 padding to specified len. 
        ``to_len`` must be divisible by 16.
        """
        if not bool(to_len) or to_len % 16:
            raise ValueError('to_len must be divisible by 16.')
        elif to_len < len(bytedata):
            raise ValueError('to_len must be > than bytedata length')

        if pad_func:
            pad_, custom = pad_func, True
        else:
            pad_, custom = cls._pad, False
        
        bytedata = pad_(bytedata)
        while len(bytedata) != to_len:
            bytedata += b'\x10'*16
        return bytedata

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

        self._aes_state = AESModeOfOperationCBC(
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
        
    def __init_aes_state(self) -> None:
        if FAST_ENCRYPTION:
            self._aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
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
            self.__init_aes_state()
        else:
            if self.__mode != 1:
                raise ModeInvalid('You should use only decrypt function.')
        
        if pad: data = Padding.pad(data)
        data = self._aes_cbc.encrypt(data)
        
        if concat_iv and not self.__iv_concated:
            self.__iv_concated = True
            return self.iv + data
        else:
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
            self.__init_aes_state()
        else:
            if self.__mode != 2:
                raise ModeInvalid('You should use only encrypt function.')
        
        data = self._aes_cbc.decrypt(data)
        if unpad: data = Padding.unpad(data)
        return data

def get_rnd_bytes(length: int=32) -> bytes:
    """Returns ``os.urandom(length)``."""
    return urandom(length)

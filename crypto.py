from os import urandom
from typing import BinaryIO, Generator, Union, Optional

from .constants import AES_RETURN_SIZE
from .errors import ModeInvalid, AESError

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import (
        pad as pad_, unpad as unpad_
    )
    FAST_ENCRYPTION = True
except ModuleNotFoundError: 
    # We can use PyAES if there is no pycryptodome.
    # PyAES is about 30x slower (CPython) than pycryptodome.
    # This is too slow and not so usable, but anyway.
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
    'AES', 
    'urandom',
    'FAST_ENCRYPTION', 
    'FAST_TELETHON', 
    'Padding', 
    'AESwState', 
    'aes_encrypt', 
    'aes_decrypt', 
    'make_box_salt'
]
class Padding:
    pad_ = pad_ if not FAST_ENCRYPTION else lambda ptxt: pad_(ptxt,16)
    unpad_ = unpad_ if not FAST_ENCRYPTION else lambda ptxt: unpad_(ptxt,16)
    
    @classmethod
    def pad(cls, plaintext: bytes, pad_func=None) -> bytes:
        '''Pads block with PKCS#7 padding.'''
        if pad_func:
            pad_, custom = pad_func, True
        else:
            pad_, custom = cls.pad_, False
        
        return pad_(plaintext)
    
    @classmethod
    def unpad(cls, plaintext: bytes, unpad_func=None) -> bytes:
        '''Unpads block with PKCS#7 padding.'''
        if unpad_func:
            unpad_, custom = unpad_func, True
        else:
            unpad_, custom = cls.unpad_, False
        
        while True:
            try:
                plaintext = unpad_(plaintext)
            except ValueError: # No more padding
                return plaintext

    @classmethod
    def cycle_pad(cls, plaintext: bytes, to_len: int, pad_func=None) -> bytes:
        '''
        Pads block with PKCS#7 padding to specified len. 
        `to_len` must be divisible by 16.
        '''
        if not bool(to_len) or to_len % 16:
            raise ValueError('to_len must be divisible by 16.')
        elif to_len < len(plaintext):
            raise ValueError('to_len must be > than plaintext length')

        if pad_func:
            pad_, custom = pad_func, True
        else:
            pad_, custom = cls.pad_, False
        
        plaintext = pad_(plaintext)
        while len(plaintext) != to_len:
            plaintext += b'\x10'*16
        return plaintext

class _PyaesState:
    def __init__(self, key: Union[bytes, 'Key'], iv: bytes):
        '''
        Class to wrap `pyaes.AESModeOfOperationCBC` 
        if there is no `FAST_ENCRYPTION`.
        
        You should use only `encrypt()` or 
        `decrypt()` method per one object.
        '''
        key = key.key if hasattr(key, 'key') else key
        self._aes_state = AESModeOfOperationCBC(key=key, iv=iv)
        self.__mode = None # encrypt mode is 1 and decrypt is 2
        
    def encrypt(self, data: bytes) -> bytes:
        '''`data` length must be divisible by 16.'''
        if not self.__mode:
            self.__mode = 1
        else:
            if self.__mode != 1:
                raise ModeInvalid('You should use only decrypt function.')
        
        assert not len(data) % 16; total = b''
        
        for _ in range(len(data) // 16):
            total += self._aes_state.encrypt(data[:16])
            data = data[16:]
        
        return total
    
    def decrypt(self, data: bytes) -> bytes:
        '''`data` length must be divisible by 16.'''
        if not self.__mode:
            self.__mode = 2
        else:
            if self.__mode != 2:
                raise ModeInvalid('You should use only encrypt function.')
                
        assert not len(data) % 16; total = b''
        
        for _ in range(len(data) // 16):
            total += self._aes_state.decrypt(data[:16])
            data = data[16:]
        
        return total

class AESwState:
    def __init__(self, key: Union[bytes, 'Key'], iv: bytes):
        '''
        Wrap around AES CBC which saves state.
        
        You should use only `encrypt()` or 
        `decrypt()` method per one object.
        '''
        self.key = key.key if hasattr(key, 'key') else key
        self.iv, self.__mode = iv, None

        if FAST_ENCRYPTION:
            self._aes_cbc = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        else:
            self._aes_cbc = _PyaesState(self.key, self.iv)
    
    @property
    def mode(self) -> int:
        '''
        Returns `1` if mode is encryption 
        and `2` if decryption. 
        '''
        return self.__mode
    
    def encrypt(self, data: bytes, pad: bool=False) -> bytes:
        '''Encrypts bytes. `data` length must equals to 16.'''
        if not self.__mode:
            self.__mode = 1
        else:
            if self.__mode != 1:
                raise ModeInvalid('You should use only decrypt function.')
        
        if pad: data = Padding.pad(data)
        data = self._aes_cbc.encrypt(data)
        return data
    
    def decrypt(self, data: bytes, unpad: bool=False) -> bytes:
        '''Decrypts bytes. `data` length must equals to 16.'''
        if not self.__mode:
            self.__mode = 2
        else:
            if self.__mode != 2:
                raise ModeInvalid('You should use only encrypt function.')
        
        data = self._aes_cbc.decrypt(data)
        if unpad: data = Padding.unpad(data)
        return data
    
def aes_encrypt(
        plain_data: Union[BinaryIO, bytes], 
        key: Union[bytes, 'Key'], iv: Optional[bytes] = None, 
        concat_iv: bool=True, yield_all: bool=False, 
        yield_size: int=2*10**8, add_padding: bool=True
        )-> Generator[bytes, None, None]:
    '''
    Yields encrypted `plain_data` by `yield_size` amount of bytes.
    
    plain_data (`BinaryIO`, `bytes`):
        Bytes to encrypt. Can be file-like object or bytes.
    
    key (`bytes`, `Key`):
        Encryption key. Must be type of `bytes` or `Key`.
        Can be 128, 192 and 256 bits length.
    
    iv (`bytes`, optional):
        Initialization Vector for AES CBC.
        `urandom(16)` if not specified.
    
    concat_iv (`bool`, optional):
        Yields IV as first chunk if `True` (by default).
    
    yield_all (`bool`, optional):
        Encrypts and yields all `plain_data` in one cycle.
        Returns `plain_data` by `yield_size` length chunks if 
        `False` (by default).
    
    yield_size (`int`, optional):
        Size of encrypted chunks to yield. Must be
        divisible by 16. By default `.constants.AES_RETURN_SIZE`.
    
    add_padding (`bool`, optional):
        Adds padding (even if length is divisible by 16) if
        True (by default). False is otherwise.
    '''
    if yield_size % 16:
        raise AESError('yield_size must be divisible by 16.')

    iv = iv if iv else urandom(16)
    key = key.key if hasattr(key, 'key') else key
    
    try:
        if FAST_ENCRYPTION:
            aes_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
        else:
            aes_cbc = _PyaesState(key, iv)
    except Exception as e:
        raise AESError(f'Invalid configuration. {e}')
    
    if concat_iv and not yield_all: 
        yield iv
    
    while True:
        if isinstance(plain_data, BinaryIO) or hasattr(plain_data, 'read'):
            chunk = plain_data.read() if yield_all else plain_data.read(yield_size)
            
        elif isinstance(plain_data, bytes):
            if not yield_all:
                chunk = plain_data[:yield_size]
                plain_data = plain_data[yield_size:]
            else:
                chunk, plain_data = plain_data, b''
        else:
            raise TypeError('plain_data not Union[BinaryIO, bytes].')

        if len(chunk) % 16 or not chunk or yield_all:
            if not chunk and not add_padding:
                return
            else:
                iv_ = iv if (concat_iv and yield_all) else b''
                yield iv_ + aes_cbc.encrypt(Padding.pad(chunk))
                return
        else:
            yield aes_cbc.encrypt(chunk)

def aes_decrypt(
        cipher_data: Union[BinaryIO, bytes], key: Union[bytes, 'Key'], 
        iv: Optional[bytes] = None, yield_all: bool=False, 
        yield_size: int=AES_RETURN_SIZE, strip_padding: bool=True
        ) -> Generator[bytes, None, None]:
    '''
    Yields decrypted `cipher_data` by `yield_size` amount of bytes.
    
    cipher_data (`BinaryIO`, `bytes`):
        Bytes to decrypt. Can be file-like object or bytes.
    
    key (`bytes`, `Key`):
        Decryption key. Must be type of `bytes` or `Key`.
        Can be 128, 192 and 256 bits length.
    
    iv (`bytes`, optional):
        Initialization Vector for AES CBC.
        first 16 bytes of `cipher_data` if not specified.

    yield_all (`bool`, optional):
        Decrypts and yields all `cipher_data` in one cycle.
        Returns `cipher_data` by `yield_size` length chunks if 
        `False` (by default).
    
    yield_size (`int`, optional):
        Size of decrypted chunks to yield. Must be
        divisible by 16. By default `.constants.AES_RETURN_SIZE`.
    
    strip_padding (`bool`, optional):
        Removes padding if `True`.
    '''    
    aes_cbc = None
    if yield_size % 16:
        raise AESError('yield_size must be divisible by 16.')

    key = key.key if hasattr(key, 'key') else key
    
    while True:
        if isinstance(cipher_data, BinaryIO) or hasattr(cipher_data, 'read'):
            iv = iv if iv else cipher_data.read(16)
            chunk = cipher_data.read() if yield_all else cipher_data.read(yield_size)
            l_strip_padding = False if (not strip_padding or cipher_data.peek(1)) else True
            
        elif isinstance(cipher_data, (bytes, memoryview)):
            if not iv:
                iv = cipher_data[:16]
                cipher_data = cipher_data[16:]
            
            chunk = cipher_data if yield_all else cipher_data[:yield_size]
            cipher_data = b'' if yield_all else cipher_data[yield_size:]
            l_strip_padding = False if (not strip_padding or cipher_data) else True         
        else:
            raise TypeError('cipher_data not Union[BinaryIO, bytes].')
        
        try:
            if not aes_cbc:
                if FAST_ENCRYPTION:
                    aes_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
                else:
                    aes_cbc = _PyaesState(key, iv)
            
            if l_strip_padding:
                yield Padding.unpad(aes_cbc.decrypt(chunk)); return
            else:
                if not chunk and not strip_padding:
                    return
                else:
                    yield aes_cbc.decrypt(chunk)

        except Exception as e:
            raise AESError(f'Invalid configuration. {e}')

def make_box_salt() -> bytes:
    '''Generates box salt.'''
    return urandom(32)

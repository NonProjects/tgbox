"""This module stores API constants."""

from pathlib import Path

__all__ = [
    'API_ID', 
    'API_HASH', 
    'VERSION', 
    'VERBYTE', 
    'DEF_TGBOX_NAME', 
    'DEF_NO_FOLDER', 
    'DEF_UNK_FOLDER', 
    'PREFIX', 
    'VERBYTE_MAX', 
    'FILE_SALT_SIZE', 
    'FILE_NAME_MAX', 
    'COMMENT_MAX', 
    'FOLDERNAME_MAX', 
    'PREVIEW_MAX', 
    'DURATION_MAX', 
    'FILESIZE_MAX', 
    'METADATA_MAX', 
    'FILEDATA_MAX', 
    'NAVBYTES_SIZE', 
    'BOX_IMAGE_PATH', 
    'WORDS_PATH', 
    'SCRYPT_SALT', 
    'SCRYPT_DKLEN', 
    'SCRYPT_N', 
    'SCRYPT_R', 
    'SCRYPT_P', 
    'DOWNLOAD_PATH', 
    'AES_RETURN_SIZE'
]
# Please DO NOT use this parameters in your projects. Thanks.
# You can get your own at my.telegram.org. Use it, instead of default.
API_ID: int=2210681; API_HASH: str='33755adb5ba3c296ccf0dd5220143841'

VERSION: str='0.1'
VERBYTE: bytes=b'\x00'

DEF_TGBOX_NAME: str='TGBOX'

DEF_NO_FOLDER:  bytes=b'NO_FOLDER'
DEF_UNK_FOLDER: bytes=b'UNKNOWN_FOLDER'

PREFIX:       bytes=b'\x00TGBOX'
VERBYTE_MAX:    int=1
FILE_SALT_SIZE: int=32
FILE_NAME_MAX:  int=300
COMMENT_MAX:    int=255
FOLDERNAME_MAX: int=64000-16
PREVIEW_MAX:    int=1000000-16
DURATION_MAX:   int=2147483647
FILESIZE_MAX:   int=1998935361

METADATA_MAX:   int=1064639
FILEDATA_MAX:   int=64584 # IV included
NAVBYTES_SIZE:  int=32 # IV included


# Get path to "other" folder where we store
# words.txt and tgbox_logo.png files.
_other = Path(Path(__file__).parent, 'other')

BOX_IMAGE_PATH: Path=Path(_other, 'tgbox_logo.png')
WORDS_PATH: Path=Path(_other, 'words.txt')

# This salt affects basekeys, you can change it to protect your RemoteBox
# from bruteforcing, but be sure to backup your own salt, because if you
# lose it, then it will be impossible to recover your decryption key for Tgbox. 
# This isn't necessary at all, because if you use *strong* password or generated 
# by program Phrase, then it's already almost impossible to brute force. 
# Think of it as 2FA. Changing salt doesn't help if your mainkey was leaked,
# but will protect you from passphrase leakage.
SCRYPT_SALT: bytes = bytes.fromhex(
    '37ce65c834c6efe05dfad02413c0950072a1fe3ed48a33368333848d9c782167'
) 
# You can change any Scrypt params. Please note that resulted
# key will be hashed with sha256, so BaseKey is always 32-byte.
# Default constants balanced to use 1GB of RAM.
SCRYPT_DKLEN: int=32
SCRYPT_N:     int=2**20
SCRYPT_R:     int=8
SCRYPT_P:     int=1

# Path that will be used to save downloaded files.
DOWNLOAD_PATH: Path=Path('BoxDownloads')

# How much AES will read for one encryption/decryption
# cycle. This amount of bytes will be yielded from
# aes_decrypt or aes_encrypt function. You can increase this
# constant if you have big amount of RAM. Default is 200 megabytes.
AES_RETURN_SIZE: int=200000000

# Must be divisible by 16.
assert not AES_RETURN_SIZE % 16 and AES_RETURN_SIZE > 16 

"""This module stores API defaults."""

from pathlib import Path
from . import __version__

try:
    from sys import _MEIPASS
except ImportError:
    _MEIPASS = None

__all__ = [
    'VERSION', 
    'VERBYTE', 
    'DEF_TGBOX_NAME',
    'REMOTEBOX_PREFIX',
    'DEF_NO_FOLDER', 
    'DEF_UNK_FOLDER', 
    'PREFIX', 
    'FILE_PATH_MAX', 
    'METADATA_MAX', 
    'BOX_IMAGE_PATH', 
    'WORDS_PATH', 
    'FFMPEG',
    'SCRYPT_SALT', 
    'SCRYPT_DKLEN', 
    'SCRYPT_N', 
    'SCRYPT_R', 
    'SCRYPT_P', 
    'ABSPATH',
    'DOWNLOAD_PATH',
    'PYINSTALLER_DATA'
]
VERSION: str=__version__
VERBYTE: bytes=b'\x01'

DEF_TGBOX_NAME:   str='TGBOX'
REMOTEBOX_PREFIX: str=f'{DEF_TGBOX_NAME}[{VERBYTE.hex()}]: '

DEF_NO_FOLDER:  Path=Path('NO_FOLDER')
DEF_UNK_FOLDER: Path=Path('UNKNOWN_FOLDER')

PREFIX: bytes=b'\x00TGBOX'

# We store metadata size in three bytes, but
# by default it's size is limited to 1MB. You
# can set it up to the 256^3-1, but to share
# your files with other people they should have
# a METADATA_MAX that >= than yours.
METADATA_MAX = 1000000 

# Max FILE_PATH length on Linux
# is 4096 bytes (4KiB). 
FILE_PATH_MAX: int=4096

ABSPATH: Path = Path(_MEIPASS) if _MEIPASS is not None \
    else Path(__file__).parent

# Get path to "other" folder where we store
# words.txt and tgbox_logo.png files.
_other: Path = ABSPATH / 'other'

# We will use it in subprocess.call
FFMPEG = 'ffmpeg'

# You can add ffmpeg.exe to 'other' folder
# before build with PyInstaller on Windows or
# just if you want TGBOX to make file thumbnails 
# or extract duration. It will be added to 
# your resulted executable.
# 
# https://www.ffmpeg.org/download.html#build-windows
#
for file in _other.iterdir():
    if file.name == 'ffmpeg.exe':
        FFMPEG = _other / 'ffmpeg.exe'

# By default, PyInstaller will not grab files
# from 'other' folder. To resolve this error 
# you will need to manually add it to .spec file.
#
# See 
#   '.spec file' example:
#        github.com/NotStatilko/tgbox-cli/blob/main/tgbox_cli.spec
#
#   'Installation' in TGBOX docs:
#       tgbox.readthedocs.io/en/latest/installation.html 
#
PYINSTALLER_DATA: dict = {
    str(Path('other', i.name)): str(i)
    for i in _other.glob('*')
}
BOX_IMAGE_PATH: Path = _other / 'tgbox_logo.png'
WORDS_PATH: Path = _other / 'words.txt'

# This salt affects basekeys, you can change it to protect your RemoteBox
# from bruteforcing, but be sure to backup your own salt, because if you
# lose it, then it will be impossible to recover your decryption key for Tgbox. 
# Change this isn't necessary at all, because if you use *strong* password or 
# generated keys.Phrase, then it's already should be impossible to brute force. 
# Think of it as 2FA. Changed salt doesn't protect you if you leaked your mainkey,
# but will protect you from passphrase leakage.
SCRYPT_SALT: bytes = bytes.fromhex(
    '37ce65c834c6efe05dfad02413c0950072a1fe3ed48a33368333848d9c782167'
) 
# You can change any Scrypt params. Please note that by default resulted
# key will be hashed with sha256, so BaseKey is always 32-byte.
# Default is balanced to use 1GB of RAM.
SCRYPT_DKLEN: int=32
SCRYPT_N:     int=2**20
SCRYPT_R:     int=8
SCRYPT_P:     int=1

# Path that will be used to save downloaded files.
DOWNLOAD_PATH: Path=Path('DownloadsTGBOX')

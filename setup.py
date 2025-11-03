from os import getenv
from setuptools import setup
from ast import literal_eval
from sys import version_info, platform


CURRENT_PYTHON = version_info[:2]
REQUIRED_PYTHON = (3, 9)

with open('tgbox/version.py', encoding='utf-8') as f:
    version = literal_eval(f.read().split('=',1)[1].strip())

if CURRENT_PYTHON < REQUIRED_PYTHON:
    raise RuntimeError(f'"tgbox" {version} lib require Python v3.9+')

# Used in setup(extras_require=...)
extras_require_fast = [
    'cryptography<47.0.0',
    'cryptg==0.5.2'
]
if platform == 'linux' and not getenv('TGBOX_NO_UVLOOP'):
    # On Linux we can use Uvloop, which is
    # significantly faster than default
    # Asyncio Event Loop. You can build
    # tgbox without it if you want to
    # (for some reason), just set the
    # TGBOX_NO_UVLOOP=1 in your Env
    uvloop = 'uvloop==0.22.1'
    extras_require_fast.append(uvloop)

setup(
    name             = 'tgbox',
    packages         = ['tgbox', 'tgbox.api'],
    version          = version,
    license          = 'LGPL-2.1',
    description      = 'Encrypted cloud storage Protocol based on a Telegram API',
    long_description = open('README.rst', encoding='utf-8').read(),
    author           = 'NonProjects',
    author_email     = 'thenonproton@pm.me',
    url              = 'https://github.com/NonProjects/tgbox',
    download_url     = f'https://github.com/NonProjects/tgbox/archive/refs/tags/v{version}.tar.gz',

    long_description_content_type='text/x-rst',

    package_data = {
        'tgbox': ['tgbox/other'],
    },
    include_package_data = True,

    install_requires = [
        'aiosqlite==0.21.0',
        'telethon==1.41.2',
        'ecdsa==0.19.0',
        'filetype==1.2.0',
        'pysocks==1.7.1'
    ],
    keywords = [
        'Telegram', 'Cloud-Storage', 'Cloud',
        'API', 'Asyncio', 'Non-official'
    ],
    extras_require = {
        'doc': [
            'sphinx-book-theme==1.1.4',
            'sphinx-togglebutton==0.3.2'
        ],
        'fast': extras_require_fast
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python :: 3.9'
    ]
)

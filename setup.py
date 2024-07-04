from setuptools import setup
from ast import literal_eval
from sys import version_info


CURRENT_PYTHON = version_info[:2]
REQUIRED_PYTHON = (3, 8)

if CURRENT_PYTHON < REQUIRED_PYTHON:
    raise RuntimeError('The "tgbox" library require Python v3.8+')


with open('tgbox/version.py', encoding='utf-8') as f:
    version = literal_eval(f.read().split('=',1)[1].strip())

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
        'aiosqlite==0.20.0',
        'telethon==1.35.0',
        'ecdsa==0.19.0',
        'filetype==1.2.0',
        'pysocks==1.7.1'
    ],
    keywords = [
        'Telegram', 'Cloud-Storage', 'Cloud',
        'API', 'Asyncio', 'Non-official'
    ],
    extras_require = {
        'fast': [
            'cryptography',
            'cryptg==0.4.0'
        ],
        'doc': [
            'sphinx-book-theme==1.1.3',
            'sphinx-togglebutton==0.3.2'
        ]
    },
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12'
    ]
)

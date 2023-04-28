from setuptools import setup
from tgbox.version import VERSION

setup(
    name             = 'tgbox',
    packages         = ['tgbox', 'tgbox.api'],
    version          = VERSION,
    license          = 'LGPL-2.1',
    description      = 'Encrypted cloud storage API based on a Telegram API',
    long_description = open('README.rst', encoding='utf-8').read(),
    author           = 'NonProjects',
    author_email     = 'thenonproton@pm.me',
    url              = 'https://github.com/NonProjects/tgbox',
    download_url     = f'https://github.com/NonProjects/tgbox/archive/refs/tags/{VERSION}.tar.gz',

    long_description_content_type='text/x-rst',

    package_data = {
        'tgbox': ['tgbox/other'],
    },
    include_package_data = True,

    install_requires = [
        'aiosqlite==0.18.0',
        'telethon==1.28.2',
        'ecdsa==0.18.0',
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
            'sphinx-rtd-theme==1.2.0',
            'sphinxcontrib-jquery==4.1'
        ]
    },
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',

    ]
)

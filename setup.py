from setuptools import setup

setup(
    name             = 'tgbox',
    packages         = ['tgbox'],
    version          = '0.4',
    license          = 'LGPL-2.1',
    description      = 'Encrypted cloud storage based on Telegram API',
    author           = 'NonProjects',
    author_email     = 'thenonproton@pm.me',
    url              = 'https://github.com/NonProjects/tgbox',
    download_url     = 'https://github.com/NonProjects/tgbox/archive/refs/tags/main%23{VERSION}.tar.gz',

    package_data = {
        'tgbox': ['tgbox/other'],
    },
    include_package_data = True,
    
    install_requires = [
        'aiosqlite==0.17.0',
        'telethon==1.24.0',
        'ecdsa==0.16.1',
        'filetype==1.0.8',
        'sphinx-rtd-theme==1.0.0'
    ],
    keywords = [
        'Telegram', 'Cloud-Storage', 'Cloud',
        'API', 'Asyncio', 'Non-official'
    ],
    extras_require = {
        'fast': [
            'pycryptodome==3.12.0',
            'cryptg==0.2.post4',
            'regex==2021.11.10'
        ]
    },
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Archiving :: Backup',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ]
)

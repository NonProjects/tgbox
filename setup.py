from distutils.core import setup

setup(
    name             = 'tgbox',
    packages         = ['tgbox']
    version          = '0.1',
    license          = 'LGPL-2.1',
    description      = 'Encrypted cloud storage based on Telegram API',
    author           = 'NonProjects',
    url              = 'https://github.com/NonProjects/tgbox',
    download_url     = 'https://github.com/NonProjects/tgbox/archive/refs/tags/indev%230.1.tar.gz',

    install_requires = [
        'aiosqlite==0.17.0',
        'telethon==1.24.0',
        'ecdsa==0.16.1',
        'filetype==1.0.8',
        'cryptg==0.2.post2',
        'pycryptodome==3.10.1'
        'sphinx-rtd-theme', 'regex'
    ],
    keywords = [
        'Telegram', 'Cloud-Storage', 
        'API', 'Asyncio', 'Non-official'
    ],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Archiving :: Backup',
        'License :: OSI Approved :: LGPL-2.1',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
    ]
)

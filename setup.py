from setuptools import setup

setup(
    name             = 'tgbox',
    packages         = ['tgbox'],
    version          = '1.0',
    license          = 'LGPL-2.1',
    description      = 'Encrypted cloud storage API based on a Telegram API',
    long_description = open('README.rst').read(),
    author           = 'NonProjects',
    author_email     = 'thenonproton@pm.me',
    url              = 'https://github.com/NonProjects/tgbox',
    download_url     = 'https://github.com/NonProjects/tgbox/archive/refs/tags/v1.0.tar.gz',

    long_description_content_type='text/x-rst',

    package_data = {
        'tgbox': ['tgbox/other'],
    },
    include_package_data = True,
    
    install_requires = [
        'aiosqlite==0.17.0',
        'telethon==1.25.0',
        'ecdsa==0.16.1',
        'filetype==1.0.8',
    ],
    keywords = [
        'Telegram', 'Cloud-Storage', 'Cloud',
        'API', 'Asyncio', 'Non-official'
    ],
    extras_require = {
        'fast': [
            'cryptography',
            'cryptg==0.3.1',
            'regex==2022.8.17'
        ],
        'doc': ['sphinx-rtd-theme==1.0.0']
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

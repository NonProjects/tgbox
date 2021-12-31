TGBOX: encrypted cloud storage based on Telegram API
====================================================

.. code-block:: python

        from tgbox import loop

        from tgbox.api import (
            TelegramAccount, 
            make_remote_box,
            make_local_box
        )
        from tgbox.keys import make_basekey
        from getpass import getpass 


        async def main():
            ta = TelegramAccount(
                phone_number = input('Phone: ')
            )
            await ta.connect()
            await ta.send_code_request()

            await ta.sign_in(
                code = int(input('Code: ')),
                password = getpass('Pass: ')
            )
            basekey = make_basekey(b'very_bad_phrase')

            erb = await make_remote_box(ta)
            dlb = await make_local_box(erb, ta, basekey)
            
            drb = await erb.decrypt(dlb=dlb)

            ff = await dlb.make_file(
                file = open('cats.png','rb'),
                comment = b'Cats are cool B-)',
                foldername = b'Pictures/Kitties' 
            )
            drbfi = await drb.push_file(ff)
            await drbfi.download()

        loop.run_until_complete(main()) 

Motivation
----------

The Telegram is beautiful app. Not only by mean of features and Client API, but it's also good in cryptography and secure messaging. In the last years, core and client devs of Telegram mostly work for "social-network features", i.e video chats and message reactions, which is OK, but there also can be plenty of "crypto-related" things. 

Target
------

This library targets to be a PoC of **encrypted file storage** inside Telegram, but can be used as standalone API.

Abstract
--------

We name *"encrypted cloud storage"* as **Box** and the API to it as **Tgbox**. There is **two** of boxes: the **RemoteBox** and the **LocalBox**. They define a basic primitives. You can share your Box and separate Files with other people absolutely secure - only You and someone you want will have decryption key, even through insecure communication canals (`e2e <https://en.wikipedia.org/wiki/End-to-end_encryption>`_). You can make unlimited amount of Boxes, upload speed equals to vanilla Telegram and maximum filesize is ``~2GB-2MB``.

Documentation
-------------

See `ReadTheDocs <https://tgbox.readthedocs.io/en/indev/>`_ for main information and help.

You can also build docs from the source

.. code-block:: console

   git clone https://github.com/NonProject/tgbox --branch=indev
   cd tgbox; python3 -m pip install -r requirements.txt
   cd docs; make html; <your-browser> _build/html/index.html

Third party & thanks to
-----------------------

- `Sphinx_rtd_theme <https://github.com/readthedocs/sphinx_rtd_theme>`_ (`MIT <https://github.com/readthedocs/sphinx_rtd_theme/blob/master/LICENSE>`_)
- `Regex <https://github.com/mrabarnett/mrab-regex>`_ (`LICENSE <https://github.com/mrabarnett/mrab-regex/blob/hg/LICENSE.txt>`_)
- `Aiosqlite <https://github.com/omnilib/aiosqlite>`_ (`MIT <https://github.com/omnilib/aiosqlite/blob/main/LICENSE>`_)
- `Telethon <https://github.com/LonamiWebs/Telethon>`_ (`MIT <https://github.com/LonamiWebs/Telethon/blob/master/LICENSE>`_)
- `Ecdsa <https://github.com/tlsfuzzer/python-ecdsa>`_ (`LICENSE <https://github.com/tlsfuzzer/python-ecdsa/blob/master/LICENSE>`_)
- `Filetype <https://github.com/h2non/filetype.py>`_ (`MIT <https://github.com/h2non/filetype.py/blob/master/LICENSE>`_)
- `Cryptg <https://github.com/cher-nov/cryptg>`_ (`LICENSE <https://github.com/cher-nov/cryptg/blob/master/LICENSE.txt>`_)
- `Pycryptodome <https://github.com/Legrandin/pycryptodome>`_ (`LICENSE <https://github.com/Legrandin/pycryptodome/blob/master/LICENSE.rst>`_)


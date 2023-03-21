TGBOX: encrypted cloud storage based on Telegram
================================================
.. image:: https://readthedocs.org/projects/tgbox/badge/?version=latest

.. code-block:: python

        from tgbox.api import (
            TelegramClient,
            make_remotebox,
            make_localbox
        )
        from asyncio import run as asyncio_run
        from tgbox.keys import Phrase, make_basekey
        from getpass import getpass # Hidden input

        # Phone number linked to your Telegram account
        PHONE_NUMBER = '+10000000000'

        # This two will not work. Get your own at https://my.telegram.org
        API_ID, API_HASH = 1234567, '00000000000000000000000000000000'

        async def main():
            tc = TelegramClient(
                phone_number = PHONE_NUMBER,
                api_id = API_ID,
                api_hash = API_HASH
            )
            await tc.connect() # Connecting with Telegram
            await tc.send_code() # Requesting login code

            await tc.log_in(
                code = int(input('Code: ')),
                password = getpass('Pass: ')
            )
            # Generating your passphrase
            p = Phrase.generate()
            print(p.phrase.decode())

            # WARNING: This will use 1GB of RAM for a
            # couple of seconds. See help(make_basekey)
            basekey = make_basekey(p)

            # Make EncryptedRemoteBox
            erb = await make_remotebox(tc)
            # Make DecryptedLocalBox
            dlb = await make_localbox(erb, basekey)
            # Obtain DecryptedRemoteBox
            drb = await erb.decrypt(dlb=dlb)

            # CATTRS is a File's CustomAttributes. You
            # can specify any you want. Here we will add
            # a "comment" attr with a true statement :^)
            cattrs = {'comment': b'Cats are cool B-)'}

            # Preparing file for upload. This will return a PreparedFile object
            pf = await dlb.prepare_file(open('cats.png','rb'), cattrs=cattrs)

            # Uploading PreparedFile to the RemoteBox
            # and return DecryptedRemoteBoxFile
            drbf = await drb.push_file(pf)

            # Retrieving some info from the RemoteBoxFile
            print('File size:', drbf.size, 'bytes')
            print('File name:', drbf.file_name)

            # You can also access all information about
            # the RemoteBoxFile you need from the LocalBox
            dlbf = await dlb.get_file(drbf.id)

            print('File path:', dlbf.file_path)
            print('Custom Attributes:', dlbf.cattrs)

            # Downloading file back.
            await drbf.download()

            # Close all connections
            # after work was done
            await erb.done()
            await dlb.done()

        asyncio_run(main())

Motivation
----------

The Telegram is beautiful app. Not only by mean of features and Client API, but it's also good in cryptography and secure messaging. In the last years, core and client devs of Telegram mostly work for "social-network features", i.e video chats and message reactions which is OK, but there also can be plenty of "crypto-related" things.

Target
------

This *[unofficial]* library targets to be a PoC of **encrypted file storage** inside the Telegram, but can be used as standalone API.

Abstract
--------

We name *"encrypted cloud storage"* as **Box** and the API to it as **Tgbox**. There is **two** of boxes: the **RemoteBox** and the **LocalBox**. They define a basic primitives. You can share your Box and separate Files with other people absolutely secure - only You and someone you want will have decryption key, even through insecure communication canals (`e2e <https://en.wikipedia.org/wiki/End-to-end_encryption>`__). You can make unlimited amount of Boxes, Upload & Download speed is **faster** than in official Telegram clients and maximum filesize is around **2GB** and around **4GB** for Premium users.

Documentation
-------------

See `ReadTheDocs <https://tgbox.readthedocs.io/>`__ for main information and help.

You can also build docs from the source

.. code-block:: console

   git clone https://github.com/NonProject/tgbox --branch=indev
   cd tgbox && python3 -m pip install .[doc] # Install with doc
   cd docs && make html && firefox _build/html/index.html

Third party & thanks to
-----------------------
- `⭐️ <https://github.com/NonProjects/tgbox/stargazers>`__ **Stargazers!**
- `Sphinx_rtd_theme <https://github.com/readthedocs/sphinx_rtd_theme>`__ (`MIT <https://github.com/readthedocs/sphinx_rtd_theme/blob/master/LICENSE>`__)
- `Regex <https://github.com/mrabarnett/mrab-regex>`__ (`LICENSE <https://github.com/mrabarnett/mrab-regex/blob/hg/LICENSE.txt>`__)
- `Aiosqlite <https://github.com/omnilib/aiosqlite>`__ (`MIT <https://github.com/omnilib/aiosqlite/blob/main/LICENSE>`__)
- `Telethon <https://github.com/LonamiWebs/Telethon>`__ (`MIT <https://github.com/LonamiWebs/Telethon/blob/master/LICENSE>`__)
- `Ecdsa <https://github.com/tlsfuzzer/python-ecdsa>`__ (`LICENSE <https://github.com/tlsfuzzer/python-ecdsa/blob/master/LICENSE>`__)
- `Filetype <https://github.com/h2non/filetype.py>`__ (`MIT <https://github.com/h2non/filetype.py/blob/master/LICENSE>`__)
- `Cryptg <https://github.com/cher-nov/cryptg>`__ (`LICENSE <https://github.com/cher-nov/cryptg/blob/master/LICENSE.txt>`__)
- `Cryptography <https://github.com/pyca/cryptography>`__ (`LICENSE <https://github.com/pyca/cryptography/blob/main/LICENSE>`__)

Resources
---------
- Official **developer channel**: `@nontgbox <https://telegram.me/nontgbox>`__
- **Example** TGBOX **container**: `@nontgbox_non <https://telegram.me/nontgbox_non>`__

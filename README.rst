TGBOX: encrypted cloud storage based on Telegram
================================================
.. epigraph::
        | This repository contains a set of classes and functions used to manage TGBOX.
        | Try the `tgbox-cli <https://github.com/NotStatilko/tgbox-cli>`__  if you're interested in working implementation!

.. code-block:: python

        from asyncio import run as asyncio_run
        from getpass import getpass # Hidden input

        from tgbox.api import TelegramClient, make_remotebox, make_localbox
        from tgbox.keys import Phrase, make_basekey

        # This two will not work. Get your own at https://my.telegram.org
        API_ID, API_HASH = 1234567, '00000000000000000000000000000000'

        # Simple progress callback to track upload/download state
        PROGRESS_CALLBACK = lambda c,t: print(round(c/t*100),'%')

        async def main():
            phone = input('Phone number: ')

            tc = TelegramClient(
                phone_number = phone,
                api_id = API_ID,
                api_hash = API_HASH
            )
            await tc.connect() # Connecting to Telegram
            await tc.send_code() # Requesting login code

            code = int(input('Login code: '))
            password = getpass('Your password: ')

            # Login to your Telegram account
            await tc.log_in(password, code)

            # Generate and show your Box phrase
            print(phrase := Phrase.generate())

            # WARNING: This will use 1GB of RAM for a
            # couple of seconds. See help(make_basekey)
            basekey = make_basekey(phrase)

            erb = await make_remotebox(tc) # Make EncryptedRemoteBox
            dlb = await make_localbox(erb, basekey) # Make DecryptedLocalBox
            drb = await erb.decrypt(dlb=dlb) # Obtain DecryptedRemoteBox

            # Write a file path to upload to your Box
            file_to_upload = input('File to upload (path): ')

            # Preparing for upload. Will return a PreparedFile object
            pf = await dlb.prepare_file(open(file_to_upload,'rb'))

            # Uploading PreparedFile to Remote and getting DecryptedRemoteBoxFile
            drbf = await drb.push_file(pf, progress_callback=PROGRESS_CALLBACK)

            # Retrieving some info from the RemoteBox file
            print('File size:', drbf.size, 'bytes')
            print('File name:', drbf.file_name)

            # You can also access all information about
            # the RemoteBoxFile you need from the LocalBox
            dlbf = await dlb.get_file(drbf.id)

            print('File size:', dlbf.size, 'bytes')
            print('File path:', dlbf.file_path)

            # Downloading your [already uploaded] file from Remote.
            await drbf.download(progress_callback=PROGRESS_CALLBACK)

            await drb.done() # Close all connections
            await dlb.done() # after work was done

        asyncio_run(main())

Motivation
----------

The Telegram is beautiful app. Not only by mean of features and Client API, but it's also used to be good in cryptography and secure messaging. In the last years, core and client devs of Telegram mostly work for "social-network features", i.e video chats and message reactions which is OK (until stories, wtf?), but there also can be plenty of "crypto-related" things implemented.

Target
------

This *[unofficial]* library targets to be a PoC of **encrypted file storage** inside the Telegram, and should be used as standalone *Python library*.

Abstract
--------

We name *"encrypted cloud storage"* as **Box** and the API to it as ``tgbox``. The *Box* splits into the **RemoteBox** and the **LocalBox**. They define a basic primitives. You can **share** your *Box* and separate *Files* with other people absolutely **secure** - only You and someone you want will have decryption key, even through insecure communication canals (`e2e <https://en.wikipedia.org/wiki/End-to-end_encryption>`__). You can make **unlimited** amount of Boxes, Upload & Download **speed is faster** than in official Telegram clients and maximum filesize is around **2GB** and around **4GB** for Premium users.

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
- `Sphinx_book_theme <https://github.com/executablebooks/sphinx-book-theme>`__ (`BSD 3-Clause <https://github.com/executablebooks/sphinx-book-theme/blob/master/LICENSE>`__)
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

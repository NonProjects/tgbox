TGBOX: encrypted cloud storage based on Telegram
================================================
.. epigraph::

        | ❕ This repository contains a set of classes and functions used to manage TGBOX.
        |       Try the `tgbox-cli <https://github.com/NotStatilko/tgbox-cli>`__  if you're interested in working implementation!

.. code-block:: python

        import tgbox, tgbox.api.sync

        # This two will not work. Get your own at https://my.telegram.org
        API_ID, API_HASH = 1234567, '00000000000000000000000000000000'

        tc = tgbox.api.TelegramClient(api_id=API_ID, api_hash=API_HASH)
        tc.start() # This method will prompt you for Phone, Code & Password

        print(phrase := tgbox.keys.Phrase.generate()) # Your secret Box Phrase
        basekey = tgbox.keys.make_basekey(phrase) # Will Require 1GB of RAM
        box = tgbox.api.make_box(tc, basekey) # Will make Encrypted File Storage

        # Will upload selected file to the RemoteBox, cache information
        # in LocalBox and return the tgbox.api.abstract.BoxFile object
        abbf = box.push(input('File to upload (path): '))

        # Retrieving some info from the BoxFile
        print('File size:', abbf.size, 'bytes')
        print('File name:', abbf.file_name)

        downloaded = abbf.download() # Downloading your file from Remote.
        print(downloaded) # Will print path to downloaded file object

        box.done() # Work is done. Close all connections!

.. epigraph::

        | ❔ This code block heavily utilize the magic ``tgbox.api.sync`` module and high-level functions
        |       from the ``tgbox.api.abstract`` module for showcase. For actual *Async* code, see `Examples <https://tgbox.readthedocs.io/en/latest/examples.html>`__.

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

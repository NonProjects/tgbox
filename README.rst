TGBOX: encrypted cloud storage based on `Telegram <https://telegram.org>`__
===========================================================================
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

Although **Telegram** started as security-oriented Messenger, in recent years developers shifted its focus from privacy enhancements to social-network features & cryptocurrency integration. You may like or dislike that, but fact is obvious — Telegram can expand on its privacy-focused roots and add some more cool things — like *Encrypted Cloud Storage*. While core developers are busy with their "`gifts <https://telegram.org/blog/wear-gifts-blockchain-and-more>`__", we may make something on our own by utilizing `Telegram Client API <https://core.telegram.org>`__, and here is my vision on it.

Target
------

This **unofficial, and not affiliated with Telegram** library targets to be a Proof of *Concept* of the *Encrypted Cloud Storage* inside the Telegram Messenger. You **can not** use it directly inside your Telegram App (like Desktop or Android client). It's a standalone Python library for developers and alike.

Abstract
--------

In the scope of this project we name *"encrypted cloud storage"* as **Box** and the API to it as ``tgbox``. The *Box* consists of two parts: the **RemoteBox** (place where we store your *encrypted files*) and the **LocalBox** (place where we store *cache information*). They define a basic primitives. You can **share** your *Box* and separate *Files* with other users absolutely **secure** (even through insecure communication canals — `e2e <https://en.wikipedia.org/wiki/End-to-end_encryption>`__) — only You and *Requester* will have decryption key. You can create an **unlimited** amount of *Box* objects, Upload & Download speed is **faster** than in official Telegram clients and maximum file size is around **2GB** for Regular users and around **4GB** for Premium ones.

Documentation
-------------

See `ReadTheDocs <https://tgbox.readthedocs.io/>`__ for main information and help.

You can also build Documentation from the source

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
- `Uvloop <https://github.com/MagicStack/uvloop>`__ (`MIT <https://github.com/MagicStack/uvloop/blob/master/LICENSE-MIT>`__)

Resources
---------
- Official **developer channel**: `@nontgbox <https://telegram.me/nontgbox>`__
- **Example** TGBOX **container**: `@nontgbox_non <https://telegram.me/nontgbox_non>`__

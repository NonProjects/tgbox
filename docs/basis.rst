Basis
=====

Encryption
----------

- We use `AES CBC <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)>`_ with **256 bit** key. First 16 bytes of any encrypted by library data is `IV <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_(IV)>`_.
- As PBKDF we use `Scrypt <https://en.wikipedia.org/wiki/Scrypt>`_.


Abstract Box
------------

.. note::
    More detailed in :doc:`remotebox` and :doc:`localbox`

- The *Box* is something that have *BoxSalt* — 32 (usually random) bytes. With this salt and user phrase we make encryption key (see :ref:`Keys hierarchy`). 

- *Box* splits into two types, — the *Remote* and *Local*. They have a two states, — the *Encrypted* and *Decrypted*. 

- *RemoteBox* store encrypted files and their metadata. *LocalBox* store only metadata.

- *LocalBox* can be restored from *RemoteBox* if you have decryption key.

Keys hierarchy
--------------

Encryption Keys
^^^^^^^^^^^^^^^

1. We start from user's ``Phrase``, that can be generated via ``Phrase.generate()``. Then we make the ``BaseKey``, with ``make_basekey``. That's a *Scrypt* function, by default configured to use 1GB of RAM for key creation. We use salt from ``constants.SCRYPT_SALT`` if not specified. If changed, may be reffered as 2FA — obtaining only *Phrase* will be not enough for *Box* decryption.

2. Having ``BaseKey``, we make a *RemoteBox* and receive *BoxSalt*. Calling ``make_mainkey(basekey, box_salt)``, we receive the ``MainKey``. With *MainKey* we make *LocalBox* (see :doc:`localbox`).

3. When we want to upload file to the Box, we make a *FileSalt* — random 32 bytes. With ``make_filekey(mainkey, file_salt)`` we receive the ``FileKey``. *FileKey* encrypts file and its metadata.

So, there is **three** encryption Keys: *BaseKey*, *MainKey*, *FileKey*.

.. note::
    - We're always encrypt Telegram session with ``BaseKey``, so attacker can't decrypt it even with ``MainKey``.
    - It's impossible to restore *MainKey* from *FileKey*, so exposing it will **only** give access to file, with which this key is associated.

Transfer keys
^^^^^^^^^^^^^

To clone other's *RemoteBox* we need to obtain its *MainKey*. This can be done in two ways:
1. Alice *(owner)* can send or hand over key in plain, just via ``DecryptedLocalBox._mainkey.encode()``. But it's can be dangerous because of `MITM <https://en.wikipedia.org/wiki/Man-in-the-middle_attack>`_, and thus not recommended.
2. Bob *(recipient)* can make the ``RequestKey``. Alice invites Bob to her *Box* Telegram channel, Bob takes *BoxSalt* from description and makes *RequestKey* via ``EncryptedRemoteBox.get_requestkey`` or ``keys.make_requestkey``. After that, Bob sends *RequestKey* to Alice, she makes the ``ShareKey`` via ``DecryptedRemoteBox.get_sharekey`` and sends *ShareKey* to Bob. He use ``keys.make_importkey`` with received *ShareKey* and makes the ``ImportKey``, which is *MainKey*.

So, there is **three** transfer keys: *RequestKey*, *ShareKey*, *ImportKey*.

.. note::
    - We use `ECDH <https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman>`_ for secure key transfer. This is simplified description of how this "magic" works. More details you can get from ``keys.make_requestkey`` docstring.
    - ECDH curve is `secp256k1 <https://en.bitcoin.it/wiki/Secp256k1>`_ (used in `Bitcoin <https://en.wikipedia.org/wiki/Bitcoin>`_).
    - You can transfer *FileKey* similarly to *MainKey*.


Tgbox File
----------

Abstract tgbox file has 13 attributes:

- ``ID`` *(integer)*
- ``FOLDER`` *(bytes)* 
- ``COMMENT`` *(bytes)*
- ``DURATION`` *(float)*
- ``FILE_IV`` *(bytes)*
- ``FILE_KEY`` *(bytes/None)*
- ``FILE_NAME`` *(bytes)*
- ``FILE_SALT`` *(bytes)*
- ``PREVIEW`` *(bytes)*
- ``SIZE`` *(int)*
- ``UPLOAD_TIME`` *(int)*
- ``VERBYTE`` *(byte)*
- ``FILE_PATH`` *(bytes)*

FILE_KEY
^^^^^^^^

``FILE_KEY`` is *LocalBox*-only field. It will be non-empty if you imported ``DecryptedRemoteBoxFile`` from other's *RemoteBox*. In this case *FILE_KEY* encrypted with *LocalBox* ``MainKey``.

FOLDER
^^^^^^

We're always encrypt ``FOLDERNAME`` with *MainKey*, so when you share file, recipient will not know its folder.

FOLDER_ID
^^^^^^^^^

As we're always encrypt ``FOLDERNAME`` with unique IV, ciphertext will be always different, and iterating over files in specified folder (see ``LocalBoxFolder``) will be *very* painful. To make life easier, Tgbox has a ``FOLDER_ID``. See ``tools.make_folder_id``.

.. code-block:: python

    # Circa func. We only take first 16 bytes from result.
    folder_id = sha256(sha256(mainkey) + foldername)[:16]

**E.g:**

1. User request all files with folder "Cats"
2. We're ``make_folder_id(mainkey, b"Cats")``
3. Select all files with same ``FOLDER_ID``

.. note::
    We're talking only about *LocalBoxFile*, *RemoteBoxFile* doesn't store ``FOLDER_ID``, but encrypted ``FOLDERNAME``.

It's considered to be secure, as 

- Attacker must have direct access to your ``EncryptedLocalBox``.
- Attacker will only read that there is *X* unknown files in unknown folder, and their IDs.
- ``FOLDER_ID`` of same ``FOLDERNAME`` is unique for every *BoxSalt*.
- Attacker will not have any access to the ``EncryptedRemoteBox``.
- *RemoteBoxFile* doesn't store ``FOLDER_ID``.
- Max file size defined in ``constants`` module, and ``~2GB-2MB`` by default.

Other
^^^^^

- Max bytesize of every property defined in ``constants`` module.
- We can use ``COMMENT`` for defining file types. See `#4 <https://github.com/NonProjects/tgbox/issues/4>`_.
- ``ID`` is Telegram message ID.
- ``DURATION`` stands for media duration, ``PREVIEW`` for media preview.
- ``VERBYTE`` stands for "Version byte". I.e "\x00" — 0 version.  

Versioning
----------

We offer **three** Git branches:

1. **Indev**. This branch used for active developing. Modules almost not tested, not stable, but errors are fixed faster. 
2. **Main**. This branch has tested bugfixes and new features from *Indev*. Can be still some minor errors.
3. **Stable**. This branch has well-tested bugfixes and new features. **Zero** errors (at least critical) expected.

``VERBYTE`` define compatibility, while it's not incremented, all new updates **MUST** support previous file formats, functions, etc. Except *Version byte* there can be lower versions, like ``0.1``, ``0.1.1``, ``0.1.1.1``.... let's stop right here.

.. note::
    The *"Zero"* version *("\x00")* will be there until first "stable" branch wasn't created. The *"First"* version *("\x01")* will be fully compatible with *Zero*, it's an exception from rules.


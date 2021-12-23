Basis
=====

Algorithms
----------

- We use `AES CBC <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)>`_ with **256 bit** key. First 16 bytes of any encrypted by library data is `IV <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_(IV)>`_.
- As PBKDF we use `Scrypt <https://en.wikipedia.org/wiki/Scrypt>`_.


Abstract Box
------------

.. note::
    More detailed in :doc:`remotebox` and :doc:`localbox`

- The *Box* is something that have *BoxSalt* — 32 (usually random) bytes. With this salt and user phrase we make encryption key (see :ref:`Encryption keys`). 

- *Box* splits into two types, — the *Remote* and *Local*. They have a two states, — the *Encrypted* and *Decrypted*. 

- *RemoteBox* store encrypted files and their metadata. *LocalBox* store only metadata.

- *LocalBox* can be restored from *RemoteBox* if you have decryption key.

Encryption keys 
---------------

1. We start from user's ``Phrase``, that can be generated via ``Phrase.generate()``. Then we make the ``BaseKey``, with ``make_basekey``. That's a *Scrypt* function, by default configured to use 1GB of RAM for key creation. We use salt from ``constants.SCRYPT_SALT`` if not specified. If changed, may be reffered as 2FA — obtaining only *Phrase* will be not enough for *Box* decryption.

2. Having ``BaseKey``, we make a *RemoteBox* and receive *BoxSalt*. Calling ``make_mainkey(basekey, box_salt)``, we receive the ``MainKey``. With *MainKey* we make *LocalBox* (see :doc:`localbox`).

3. When we want to upload file to the Box, we make a *FileSalt* — random 32 bytes. With ``make_filekey(mainkey, file_salt)`` we receive the ``FileKey``. *FileKey* encrypts file and its metadata.

So, there is **three** encryption Keys: *BaseKey*, *MainKey*, *FileKey*.

.. note::
    - We're always encrypt Telegram session with ``BaseKey``, so attacker can't decrypt it even with ``MainKey``.
    - It's impossible to restore *MainKey* from *FileKey*, so exposing it will **only** give access to file, with which this key is associated.

Transfer keys & File sharing
----------------------------

Let's imagine that Alice have encrypted file in her *RemoteBox* that she want to share with Bob. As every *RemoteBoxFile* has unique encryption key (``FileKey``) file sharing shouldn't be a big problem, but how we can make it *secure*? There is two ways:

1. Get ``FileKey`` of ``DecryptedRemoteBoxFile`` and send it to Bob through Telegram's **secret chat**;
2. Encrypt ``FileKey`` with a *shared secret key* (see `asymmetric cryptography <https://en.wikipedia.org/wiki/Public-key_cryptography>`_).

Sending encryption keys via *plain chats* in Telegram **isn't secure**. Secret chat may be not available or not so conveniently. So in TGBOX we use `ECDH <https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman>`_ for making *shared secret*. File sharing routine for users simplifies to follows:

1. Alice forward file from her *RemoteBox* channel to Bob;
2. Bob forwards received file to his *RemoteBox* channel;
3. B gets ``EncryptedRemoteBoxFile`` and calls ``get_requestkey`` on it;
4. A receives ``RequestKey`` from B *(can be shared via insecure canals)*;
5. A makes ``ShareKey`` with B's ``RequestKey`` and sends it to B *(can be shared via insecure canals)*;
6. B makes ``ImportKey`` with A's ``ShareKey``, decrypts ``EncryptedRemoteBoxFile`` and imports it.

In more low-level
^^^^^^^^^^^^^^^^^

Let's analyze *RemoteBox* sharing, there is no difference with file sharing.

- **0. Bob makes BaseKey**

  To clone other's *RemoteBox* Bob firstly should create ``BaseKey`` for it.

- **1. Alice invites Bob to her RemoteBox channel**

  This can be done with Telethon or with Telegram. If you
  are developer and want to make an App with TGBOX, then you
  need to implement this.

- **2. B gets EncryptedRemoteBox and calls get_requestkey on it**

  Every *RemoteBox* has *BoxSalt*. The *RemoteBox* store it in
  channel description, encoded by url safe base64. From concated 
  *BoxSalt* and B's new ``BaseKey`` we make a `sha256 hash <https://en.wikipedia.org/wiki/SHA-2#Test_vectors>`_. This
  hash acts as *private key* for ECDH on `secp256k1 curve <https://en.bitcoin.it/wiki/Secp256k1>`_. We
  create *public key* from this *private key*, `compress it <https://bitcoin.stackexchange.com/a/69322>`_,
  and return (``get_requestkey``) ``RequestKey(compressed_pubkey)``. Generally,
  ``RequestKey`` is compressed ECDH pubkey.

- **3. A receives RequestKey from B**

  Can be done with Telethon / Telegram or any other
  insecure communication canal.

- **4. A makes ShareKey with B's RequestKey and sends it to B**

  1. A makes own *private key* similarly to B, with 
     ``sha256(a_mainkey + box_salt)``, extracts B's pubkey from
     ``RequestKey`` and makes a shared 32byte-secret with 
     ``ECDH(a_privkey, b_pubkey, secp256k1)``. This is
     encryption key for AES CBC;

  2. A makes sha256 hash from B's ``RequestKey`` and takes 
     first 16 bytes from result, this is IV.

  3. A encrypts her ``MainKey`` with shared secret and IV. Let's call
     result as *eMainKey*. After this she constructs ``ShareKey`` as 
     follows: ``ShareKey(e_mainkey + a_pubkey)``. We don't concat
     IV to the ``ShareKey`` because Bob can extract it from ``RequestKey``.

- **5. B makes ImportKey with A's ShareKey, decrypts EncryptedRemoteBox and clones it.**
  
  Bob repeats second step, extracts IV and receives b_privkey. After,
  makes shared secret as 4.1 and decrypts ``eMainKey``. This can be
  done with ``keys.make_importkey`` function. Transfer complete.


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


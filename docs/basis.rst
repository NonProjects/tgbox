Basis
=====

Algorithms
----------

- We use `AES CBC <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)>`_ with **256 bit** key. First 16 bytes of any encrypted by library data is `IV <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_(IV)>`_.
- As PBKDF we propose *and* use by default `Scrypt <https://en.wikipedia.org/wiki/Scrypt>`_.


Abstract Box
------------

.. note::
    More detailed in :doc:`remotebox` and :doc:`localbox`

- The *Box* is something that have *BoxSalt* — 32 (usually random) bytes. With this salt and user phrase we make encryption key (see :ref:`Encryption keys hierarchy`).

- *Box* splits into two types, — the *Remote* and *Local*. They have a two states, — the *Encrypted* and *Decrypted*.

- *RemoteBox* store encrypted files and their metadata. *LocalBox* store only metadata.

- *LocalBox* can be fully restored from the *RemoteBox* if you have a decryption key (but this will be slow if you uploaded a big amount of files).

Encryption keys hierarchy
-------------------------

0. The user should provide a password to his Box. We can recommend him to use inbuilt in TGBOX *Phrase*, which is 12 random mnemonic words that can be generated via ``tgbox.keys.Phrase.generate()``. With the user's phrase (or password) we make the first encryption Key, – ``BaseKey``;

1. By default in API for ``BaseKey`` creation we use the ``tgbox.keys.make_basekey`` function, which utilize a *Scrypt* KDF under the hood. It's configured to use a **1GB** of RAM for key creation for a couple of seconds. We use such configuration for purpose of making user's phrase bruteforce **a lot** harder. The Scrypt KDF requires *salt*, and we use the one defined in the ``defaults.Scrypt.SALT``. Specifying different scrypt_salt on ``BaseKey`` creation will make bruteforce impossible if you will keep it secret. In the end we hash a Scrypt result with a ``sha256``. Please note that you can use any KDF you want, we don't force developers to use Scrypt, just make sure that resulted key is 32-byte long and wrapped in the ``tgbox.keys.BaseKey`` class. We see a Scrypt and our configuration as a safe and good standart. We use ``BaseKey`` for encrypting Telegram session and making the next key: ``MainKey``;

2. In the next step user starts a process of the *Box* creation. Every *Box* contains a so-called *BoxSalt* – 32 random (or specified by user) bytes. We concatenate ``BaseKey`` with the *BoxSalt* and make a SHA256: ``sha256(basekey + box_salt)``, the result of this operation is ``MainKey``. We use this key to encrypt a basic data of :doc:`localbox` as well as ``file_path`` attribute of *RemoteBoxFile* on pushing to the :doc:`remotebox`. With the ``MainKey`` we create a ``FileKey``;

3. When user wants to upload file to the :doc:`remotebox` he prepares it with the ``DecryptedLocalBox.prepare_file`` and then uses ``DecryptedRemoteBox.push_file`` with resulted ``PreparedFile`` object. While preparing, the code generates a *FileSalt* – 32 random bytes. Then (as with ``MainKey`` creation) we concatenate the ``MainKey`` and *FileSalt* and make the SHA256 hash of result: ``sha256(mainkey + file_salt)``. This is ``FileKey``. We use it to encrypt all of the *RemoteBoxFile* metadata attributes (except ``file_path``).

So, there is **three** encryption Keys: *BaseKey*, *MainKey*, *FileKey*.

.. note::
    - We're always encrypt Telegram session with ``BaseKey``, so attacker can't decrypt it even with ``MainKey``.
    - The *MainKey* is used to generate (and restore) a unique ``FileKey`` for each candidate file.
    - It's impossible to extract *MainKey* from *FileKey*, so exposing it will **only** give access to file, with which this key is associated.
    - See also ``make_basekey``, ``make_mainkey`` and ``make_filekey`` functions in the ``tgbox.keys`` module.

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

A bit about PackedAttributes
----------------------------

In TGBOX protocol we pack metadata and user's custom attributes in a *dictionary* form to bytestring with algorithm called *PackedAttributes*. It is a more than simple:

0. We define a main bytestring called a ``pattr``, it equals ``b'\xff'``;
1. User gives us a ``dict``, i.e ``{'type': b'cat', 'color': b'black'}``;
2. We iterate over ``dict``, obtain next key and value, write it to ``k``, ``v``;
3. Do a ``pattr += int_to_bytes(len(k),3) + k.encode()``;
4. Do a ``pattr += int_to_bytes(len(v),3) + v``;
5. If ``dict`` not empty: jump to *2.* else ``return pattr``.

**Result** *(HEX)*: ``FF00000474797065000003636174000005636F6C6F72000005626C61636B``

So we just make a string like ``0xFF<key-length>key<value-length>value<...>``.

.. tip::
   - Pack: ``tgbox.tools.PackedAttributes.pack``
   - Unpack: ``tgbox.tools.PackedAttributes.unpack``.

TGBOX File
----------

Abstract tgbox file of **v1.X** has **13** attributes:

- ``ID`` *(integer: required)* -- *Uploaded to Telegram file (message) ID*
- ``FILE_SALT`` *(bytes: required)* -- *File's salt. Used for FileKey creation*
- ``FILE_IV`` *(bytes: required)* -- *File's AES Initialization Vector*
- ``FILE_NAME`` *(bytes: required)* -- *File's name*
- ``FILE_PATH`` *(bytes: required)* -- *File's path*
- ``FILEKEY`` *(bytes: optional, LocalBox only)* -- *FileKey of imported file*
- ``SIZE`` *(int: required)* -- *Pure file's size, no metadata included*
- ``UPLOAD_TIME`` *(int: required)* -- *UNIX time when file was uploaded to RemoteBox*
- ``VERBYTE`` *(bytes: required)* -- *Protocol global version as one byte*
- ``DURATION`` *(float: optional, FFMPEG required)* -- *File's duration (if video/audio)*
- ``PREVIEW`` *(bytes: optional, FFMPEG required)* -- *File's preview (if file is media)*
- ``BOX_SALT`` *(bytes: required)* -- *Box salt. Used for MainKey creation*
- ``CATTRS`` *(bytes)* -- *User's custom attributes packed with PackedAttributes*

.. note::
    ``FILEKEY`` is a *LocalBox*-only field. It will be non-empty if you imported ``DecryptedRemoteBoxFile`` from other's *RemoteBox*. In this case *FILEKEY* will be encrypted with ``MainKey`` of the recipient *Box*.

.. note::
   We pack file attributes into the *metadata*. The max metadata bytelength is defined in the ``defaults.Limits.METADATA_MAX`` variable. By default *METADATA_MAX* is limited to 1MB, however, it can be increased up to 256^3-1 bytes (16MiB). Prior to v1.0 attributes have had own limits, but this isn't the case for the new version. Started from the v1.0 only ``FILE_PATH`` have separate limit defined in the ``defaults.Limits.FILE_PATH_MAX``, - 4096 bytes by default. Packed file attributes bytelength **shouldn't** be more than *METADATA_MAX*. See also :doc:`remotebox`.

Versioning
----------

We offer **two** Git branches:

1. **Indev**. This branch used for active developing. Modules almost not tested, not stable, but errors are fixed faster.
2. **Main**. This branch has tested bugfixes and new features from *Indev*. Can be still some minor errors.

The most **stable** releases should be presented **on the PyPi**, and can be installed via ``pip``. This rule doesn't work for releases < 1.0 because early we used a different versioning system.

The ``VERBYTE`` define compatibility. While it's not incremented, all new updates **MUST** support previous file formats, methods, etc. Except *Version byte* there can be lower versions, like ``1.1``, ``1.1.1``, etc. Verbyte= ``b'\x00'`` and Verbyte= ``b'\x01'`` **shouldn't** be compatible, otherwise we can use a lower version, i.e ``1.1``.

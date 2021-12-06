LocalBox
========

The *LocalBox* store **information** about uploaded to the :doc:`remotebox` files, but doesn't store **files**. *LocalBox* may be reffered as *RemoteBox* cache. We use `aiosqlite <https://github.com/omnilib/aiosqlite>`_ as database and three tables in it.

.. note::
   ``DecryptedLocalBox`` can be fully restored from ``DecryptedRemoteBox``.

Tables
======

*LocalBox* have 3 tables: *BOX_DATA*, *FILES*, *FOLDERS*.

BOX_DATA
--------

*BOX_DATA* store information about *Box*, *Session*, etc.

============ ============== =========== ======== ========= ======= 
LAST_FILE_ID BOX_CHANNEL_ID BOX_CR_TIME BOX_SALT MAINKEY   SESSION
============ ============== =========== ======== ========= =======
BLOB         BLOB           BLOB        BLOB     BLOB|NULL BLOB
============ ============== =========== ======== ========= =======

- ``LAST_FILE_ID`` — encrypted ID of last uploaded file;
- ``BOX_CHANNEL_ID`` — encrypted *RemoteBox* ID;
- ``BOX_CR_TIME`` — *LocalBox* creation time;
- ``BOX_SALT`` — *BoxSalt* for ``MainKey`` creation;
- ``MAINKEY`` — encrypted by ``BaseKey`` ``MainKey``. Used if *RemoteBox* was cloned;
- ``SESSION`` — encoded & encrypted Telethon's ``StringSession``.

FILES
-----

*FILES* store information about uploaded to the *RemoteBox* files.

================ ========= ======= ======== ======= ========= ========= ========= ======= ==== =========== ======= =========
ID {PRIMARY_KEY} FOLDER_ID COMMENT DURATION FILE_IV FILE_KEY  FILE_NAME FILE_SALT PREVIEW SIZE UPLOAD_TIME VERBYTE FILE_PATH
================ ========= ======= ======== ======= ========= ========= ========= ======= ==== =========== ======= =========
INT              BLOB      BLOB    BLOB     BLOB    BLOB|NULL BLOB      BLOB      BLOB    BLOB BLOB        BLOB    BLOB
================ ========= ======= ======== ======= ========= ========= ========= ======= ==== =========== ======= =========

.. note::
    - ``ID`` is Telegram message ID. Must be unique.
    - You can read more about ``FOLDER_ID`` in :doc:`basis`.
    - ``FILE_KEY`` will not ``NULL`` only when you import *RemoteBoxFile* from other's ``RemoteBox``. In this case it's encrypted by ``MainKey``.

FOLDERS
-------

*FOLDERS* store information about every unique, case-sensitive foldername.

====== ========= =========
FOLDER FOLDER_IV FOLDER_ID
====== ========= =========
BLOB   BLOB      BLOB
====== ========= =========

- ``FOLDER`` — encrypted by ``MainKey`` & ``FOLDER_IV`` foldername;
- ``FOLDER_IV`` — AES CBC Initialization Vector for ``FOLDER`` decryption;
- ``FOLDER_ID`` — result of ``tools.make_folder_id`` function. See :doc:`basis`.


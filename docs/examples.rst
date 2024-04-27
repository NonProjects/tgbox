Examples
========

The "Abstract" Module
---------------------

The ``v1.5`` introduces two *new* modules: the :mod:`tgbox.api.abstract`, which include *high-level* classes & functions with purpose to **unite** the :doc:`localbox` and the :doc:`remotebox` into the **single** class: :class:`~tgbox.api.abstract.Box`; and the magic :mod:`tgbox.api.sync` module, which turn all *Async* code in :mod:`tgbox.api.abstract` to *Sync* on import.

Writing code with the features of ``abstract`` and ``sync`` modules may be easier and more straightforward, *however*, it goes with a *cost* of speed. Methods from the :class:`~tgbox.api.abstract.Box` will use functions from the :class:`~tgbox.api.local.DecryptedLocalBox` where possible, but will return the :class:`~tgbox.api.abstract.BoxFile` objects, which **always** download file information & *Metadata* from the :doc:`remotebox`. This will **significantly** slow iteration over your *Box*. Make sure you understand this.

.. note::
   The :class:`~tgbox.api.abstract.Box` (and also :class:`~tgbox.api.abstract.BoxFile`) has the ``dlb`` (:class:`~tgbox.api.local.DecryptedLocalBox`) and ``drb`` (:class:`~tgbox.api.remote.DecryptedRemoteBox`) properties. You can use generators from the ``Box.dlb`` if you *only* want to fetch *information* about files.

Logging In & Making Client
++++++++++++++++++++++++++

There is two possible ways to make a connection to your Telegram *account*

Interactive way
^^^^^^^^^^^^^^^

.. code-block:: python

        import tgbox, tgbox.api.sync

        # This two will not work. Get your own at https://my.telegram.org
        API_ID, API_HASH = 1234567, '00000000000000000000000000000000'

        tc = tgbox.api.TelegramClient(api_id=API_ID, api_hash=API_HASH)
        tc.start() # This method will prompt you for Phone, Code & Password

        print(tc.get_me()) # Print information about Telegram account

.. note::
   The *Interactive way* is a nice for quick scripting. The ``.start()`` method will prompt you for all credentials. In your code you will probably want to use the *Manual way*

Manual way
^^^^^^^^^^

.. code-block:: python

        import tgbox, tgbox.api.sync

        # This two will not work. Get your own at https://my.telegram.org
        API_ID, API_HASH = 1234567, '00000000000000000000000000000000'
        phone_number = input('Phone number of your Telegram account: ')

        tc = tgbox.api.TelegramClient(
            phone_number=phone_number,
            api_id=API_ID,
            api_hash=API_HASH
        )
        tc.connect() # Connecting to Telegram
        tc.send_code() # Requesting login code

        code = int(input('Login code: '))
        password = input('Your password: ')

        # Log into your Telegram account
        tc.log_in(password, code)

        print(tc.get_me()) # Print information about Telegram account

.. admonition:: Where is my Asynchronous Python code??
    :class: dropdown

    In *The "Abstract" Module* we will **syncify all code** for better look. It is automatically done after ``import tgbox.api.sync`` statement. Note: you can also write the same code in *Async* way, for example:

        .. code-block:: python

                import asyncio, tgbox

                # This two will not work. Get your own at https://my.telegram.org
                API_ID, API_HASH = 1234567, '00000000000000000000000000000000'
                phone_number = input('Phone number of your Telegram account: ')

                async def main():
                    tc = tgbox.api.TelegramClient(
                        phone_number=phone_number,
                        api_id=API_ID,
                        api_hash=API_HASH
                    )
                    await tc.connect() # Connecting to Telegram
                    await tc.send_code() # Requesting login code

                    code = int(input('Login code: '))
                    password = input('Your password: ')

                    # Log into your Telegram account
                    await tc.log_in(password, code)

                    print(await tc.get_me()) # Print info about Telegram account

                if __name__ == '__main__':
                    asyncio.run(main())

Making Box
++++++++++

To make a :class:`~tgbox.api.abstract.Box` (a class that unite :doc:`localbox` and :doc:`remotebox`) we would need to use a :func:`~tgbox.api.abstract.make_box` function.

.. code-block:: python

        # "Making Client" code was omitted, insert it here ...

        # You can use any bytestring as a secret passphrase, not only from
        # this class. This will be basis to your Box-unlocking BaseKey
        print(phrase := tgbox.keys.Phrase.generate()) # Your secret Box Phrase

        # BaseKey is an absolute Key that derive all other secret keys. DO NOT
        # GIVE ANY of your Phrase, BaseKey or MainKey (except Box Sharing)
        # to anyone! Read a chapter about all Keys in the Protocol docs
        basekey = tgbox.keys.make_basekey(phrase) # Will Require 1GB of RAM
        # ^
        # | The 'make_basekey' use Scrypt under the hood, which is very
        # | configurable. You can change parameters so 'make_basekey'
        # | will require less RAM, or even more of it. Also, this
        # | function is only *proposed* by Protocol, not *required*,
        # | you can use whatever 32-byte string you want and wrap it
        # | in the 'tgbox.keys.BaseKey' class. Just be sure that
        # | it's *really* better than default 'make_basekey' firstly.

        # The Box is basically your encrypted file storage. You can push to
        # it, get/iterate files from it & then access information/download.
        # You can also import 'make_box' func from tgbox.api.abstract module.
        box = tgbox.api.make_box(tc, basekey) # Will make Encrypted File Storage

        print(box) # Show __str__ of your new & cute Boxy! ~~
        box.done() # Always call it after all work was done.

.. admonition:: What is *insert it here* thing??
    :class: dropdown

    To omit repeated code we would assume that *before* this code block you have all required imports and the ``TelegramClient`` object in ``tc`` variable. We will do such thing to **all example code** in future to reduce unnecessary repetition. I.e, absolute code would be:

    .. code-block:: python

        # -- Inserted Block --------------------------------------- #

        import tgbox, tgbox.api.sync

        API_ID, API_HASH = 1234567, '00000000000000000000000000000000'
        phone_number = input('Phone number of your Telegram account: ')

        tc = tgbox.api.TelegramClient(
            phone_number=phone_number,
            api_id=API_ID,
            api_hash=API_HASH
        )
        tc.connect() # Connecting to Telegram
        tc.send_code() # Requesting login code

        code = int(input('Login code: '))
        password = input('Your password: ')

        tc.log_in(password, code)

        # --------------------------------------------------------- #

        print(phrase := tgbox.keys.Phrase.generate()) # Your secret Box Phrase
        basekey = tgbox.keys.make_basekey(phrase) # Will Require 1GB of RAM
        box = tgbox.api.make_box(tc, basekey) # Will make Encrypted File Storage

        print(box)
        box.done()

Opening Box
+++++++++++

After you created *Box* with :func:`~tgbox.api.abstract.make_box` the :doc:`protocol` should create a private Telegram *Channel* on your account (the :doc:`remotebox`) and a SQLite file (by default called ``TGBOX``) on your Computer (the :doc:`localbox`). The :doc:`localbox` store all information (in encrypted by :class:`~tgbox.keys.BaseKey` form) that is enough to automatically connect to your Telegram account and do things. We can open it by using the :func:`~tgbox.api.abstract.get_box` function:

.. code-block:: python

        import tgbox, tgbox.api.sync

        # It is always recommended to *generate* your BaseKey from Phrase
        # (like here) instead of saving it & loading (unless it's testing).
        # Do not forget that with BaseKey someone can decrypt your Telegram
        # session inside the LocalBox and access your account!
        basekey = tgbox.keys.make_basekey(b'Here comes my secret Phrase!')

        # To open Box you need to give a BaseKey and the name/path of
        # LocalBox file on your Computer as second argument. As we
        # didn't changed name of our Box, 'TGBOX' here is default
        box = tgbox.api.get_box(basekey)

        print(box) # Show __str__ of your opened Boxy! Wowie! ~~
        box.done() # Always call it after all work was done.


Understanding Box
+++++++++++++++++

As already been said, the :class:`~tgbox.api.abstract.Box` is a class that combines the methods from both of the :class:`~tgbox.api.local.DecryptedLocalBox` and :class:`~tgbox.api.remote.DecryptedRemoteBox`. You can access them like this:

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        print(box.dlb) # DecryptedLocalBox
        print(box.drb) # DecryptedRemoteBox

        # Here we request ID of last file that was uploaded to the
        # LocalBox. We Can't and we Don't syncify classes/functions
        # from the 'tgbox.api.local' & 'tgbox.api.remote', so we
        # need to additionally use the 'sync_coro' function.
        lfid_local = tgbox.api.sync.sync_coro(box.dlb.get_last_file_id())

        # We do the same for RemoteBox. As we didn't uploaded any file
        # to the Box yet, the output will be 0 for both methods. Why
        # theoretically we would need this? For example, if you share
        # your Box with someone else and they upload files, -- then
        # by using this method we can track if RemoteBox is ahead.
        lfid_remote = tgbox.api.sync.sync_coro(box.drb.get_last_file_id())

        # You can access TelegramClient object with your Telegram account
        # directly from the Box (or as Box.drb.tc, for.. whatever reason)
        print(box.tc.get_me())

.. note::
    For the typical routine you will not need to use the *LocalBox* or *RemoteBox* directly, it's only for special cases (like in this example) when we need output from both *Local* and *Remote* or when we need output **only** from one *Box* (mostly from *LocalBox*).

Cloning & Sharing Box
+++++++++++++++++++++

You may not expect this, but :doc:`protocol` also support *Box cloning*! *Clone* is a process of accessing the :doc:`remotebox` and making a :doc:`localbox` from it. This can be used for restoring your *local* data or even for **sharing** your *Box* with someone else.

.. tip::
   *Box sharing* process as step-by-step: :ref:`Sharing *Box*`

Clone your own Box
^^^^^^^^^^^^^^^^^^

| For some reason you may want to make a *LocalBox* from your *RemoteBox*.
| This can be easily done with the next example

.. code-block:: python

        import tgbox, tgbox.api.sync

        # Obviously, to Clone Box we need to have at least MainKey. As
        # we are Box owner, we can also make & Clone with a BaseKey
        basekey = tgbox.keys.make_basekey(b'Here comes my secret Phrase!')

        # Now we need to obtain the Telegram Channel which represent
        # your RemoteBox. We can get it directly by the public link
        # or in any other way as Telethon's Channel object. See docs
        erb = tgbox.api.get_remotebox(tc=tc, entity='@channel') # EncryptedRemoteBox

        # Decrypt & obtain DecryptedRemoteBox object. As '.decrypt()'
        # is from EncryptedRemoteBox class, it will stay Async, so
        # we need to use the 'sync_coro()' from the 'tgbox.api.sync'
        drb = tgbox.sync.sync_coro(erb.decrypt(key=basekey)) # DecryptedRemoteBox

        # Will clone RemoteBox & make LocalBox. May take some
        # time. 'progress_callback' can be specified.
        dlb = tgbox.api.clone_remotebox(drb, basekey)

        # Iterate for files over our new LocalBox
        for dlbf in tgbox.api.sync.sync_agen(dlb.files()):
            print(dlbf.id, dlbf.file_name, dlbf.file_path)

        box.done() # Always call it after all work was done.

Box Sharing
^^^^^^^^^^^

.. warning::
   On *Box Sharing* you will need to give someone else a *MainKey* of your *Box*. With *MainKey*, other user will have access to **all** of already uploaded and **all next files** that will be uploaded to the shared *Box*. **Proceed only if you understand this!!**

.. tip::
   It's always better to make a special dedicated *Box* to share. For example, you can make a new empty *Box* and share it with your *friend*, instead of sharing your private *Box* with everyone.

At some point of time you may want to share your *Box* with someone else. Here's how:

I. *(Owner)* **Add your friend to your RemoteBox**

First of all, to share your *Box* with your friend you need to add them to your *RemoteBox*, which is Telegram *Channel*. The :doc:`protocol` doesn't have a standardized way to do this, you can make it from the official Telegram clients or via the *Telethon* library (``box.tc`` or ``drb.tc``). You can grant your friend some Admin privileges to allow File uploading, or at least Admin with **zero** rights to allow *Fast Sync*.

II. *(Friend)* **Get RequestKey for RemoteBox**

*RequestKey* is a *Key* that will be shared with *Box* owner to get *ShareKey*

.. code-block:: python

        import tgbox, tgbox.api.sync

        # We need to get a RemoteBox we want to request in Encrypted
        # form. 'entity=' can be a public or private link or a
        # Telethon's Channel as object. See docs for Telethon
        erb = tgbox.api.get_remotebox(tc=tc, entity='@channel') # EncryptedRemoteBox

        # Now we (friend) need to create a BaseKey for shared Box. It
        # should NOT be disclosed. You and Owner will have different
        basekey = tgbox.keys.make_basekey(b'Here comes my secret Phrase!')

        # Get RequestKey to target Box with our BaseKey
        reqkey = tgbox.api.sync.sync_coro(erb.get_requestkey(basekey))


| Now we need to send a *RequestKey* (``reqkey.encode()``) to the *Box* owner.
| This *Key* **can be shared via insecure communication canals**.

III. *(Owner)* **Make a ShareKey from RequestKey**

.. code-block:: python

        import tgbox, tgbox.api.sync

        # First of all, we need to load our Box that we want to share
        basekey = tgbox.keys.make_basekey(b'Here comes my secret Phrase!')
        box = tgbox.api.get_box(basekey)

        # Place here RequestKey from your friend
        reqkey = tgbox.keys.Key.decode('R<...>')

        # This is ShareKey. Send it to Requester (your friend)
        shrkey = box.get_sharekey(reqkey)

| Now we need to send a *ShareKey* (``shrkey.encode()``) to the *Box* requester.
| This *Key* **can be shared via insecure communication canals**.

IV. *(Friend)* **Make a ShareKey from RequestKey**

The final step is to get a *ImportKey* and decrypt-then-clone target *Box*

.. code-block:: python

        # Step II. code was omitted, insert it here ...

        # Place here ShareKey from Box owner
        shrkey = tgbox.keys.Key.decode('S<...>')

        # Get a BoxSalt from the EncryptedRemoteBox object
        box_salt = tgbox.api.sync.sync_coro(erb.get_box_salt())

        # Here we make ImportKey, which is de facto a
        # MainKey of target Box.
        impkey = tgbox.keys.make_importkey(
            key=basekey, sharekey=shrkey, salt=box_salt
        )
        # Decrypt the EncryptedRemoteBox with a ImportKey and
        # finally obtain the DecryptedRemoteBox object
        drb = tgbox.api.sync.sync_coro(erb.decrypt(key=impkey))

        # Will clone RemoteBox & make LocalBox. May take some
        # time. 'progress_callback' can be specified.
        dlb = tgbox.api.clone_remotebox(drb, basekey)

        # Iterate for files over our new LocalBox
        for dlbf in tgbox.api.sync.sync_agen(dlb.files()):
            print(dlbf.id, dlbf.file_name, dlbf.file_path)

        box.done() # Always call it after all work was done.

**Box sharing process is done!**

Syncing Box
+++++++++++

You need to *Sync* your *Box* periodically if you share it with someone else, and if they upload files

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        # You need to '.sync()' if other user uploaded file
        # to RemoteBox to cache updates in LocalBox
        box.sync() # Will Fast Sync your LocalBox

        # By default, '.sync()' use the Fast Sync algo,
        # which check for updates in the Channel Admin
        # Log. It's available only for 48 hours. If it's
        # not suitable for you, then use Deep Sync
        box.sync(deep=True) # Will Deep Sync your LocalBox
        # ^
        # | Deep Sync compare every file in Local with
        # | every file in Remote. This can be time &
        # | network consuming task. Consider to use a
        # | 'start_from_id' kwarg to speed process up.

        print(tgbox.api.sync.sync_coro(box.dlb.get_files_total()))
        print(tgbox.api.sync.sync_coro(box.drb.get_files_total()))

Uploading Files
+++++++++++++++

The :class:`~tgbox.api.abstract.Box` has high-level :meth:`~tgbox.api.abstract.Box.push` method (in contrast to the :meth:`~tgbox.api.remote.DecryptedRemoteBox.push_file` from :class:`~tgbox.api.remote.DecryptedRemoteBox`) which is more easy to use and support multiple file uploading from *[drumroll]* the box!

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        # The 'push()' method accept many types of "files". Here,
        # for example, we specify path to file as a string. After
        # upload, the 'tgbox.api.abstract.BoxFile' will be returned
        abbf = box.push('/path/to/Ozzmosis.png') # abstract.BoxFile

        files = [
            '/path/to/No More Tears.flac',
            '/path/to/Flying High Again.flac',
            '/path/to/No Place For Angels.flac'
        ]
        # The 'push()' method also accept list with "files"
        # and uploads them in parallel. On older versions
        # this would require a little bit more of work.
        abbf = box.push(files)
        # ^
        # | The 'push()' also can accept the 'progress_callback'
        # | and other parameters. See module documentation.

        print(abbf) # Show list of your uploaded files!
                    # (cuteness is not included, sorry.)

        # Get a total number of uploaded files. As already
        # been said, 'Box' use methods from LocalBox where
        # possible, so here will be used method from Local
        print(box.get_files_total())

.. warning::
    You will receive a **429** (**Flood Wait**) **error** and will be restricted for uploading files for some time if you will spam Telegram servers. Do **NOT** upload many *big* files at the same time.

Obtaining Files
+++++++++++++++

You can get :class:`~tgbox.api.abstract.BoxFile` objects by iterating over the :class:`~tgbox.api.abstract.Box` or by direct request via :meth:`~tgbox.api.abstract.Box.get_file`.

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        # ---- get_file() ------------------------------------------- #

        lfid = box.get_last_file_id() # Get ID of last uploaded file to Box
        abbf = box.get_file(lfid) # Directly get file by ID
        print(lfid, abbf.file_name) # Print name of BoxFile object

        # ----------------------------------------------------------- #

        # ---- files() ---------------------------------------------- #

        # The files() is a generator that you can use to iterate over
        # the whole Box and get every single file from it. Here,
        # min_id and max_id is just a reminder that all generators
        # that will be shown here is configurable. See module docs.
        for abbf in box.files(min_id=None, max_id=None):
            print(abbf.id, abbf.file_name)
                # ^
                # | Note that BoxFile *always* download file metadata
                # | (that already present in abbf.dlbf) from Remote;
                # | if you only want to get *information* about file
                # | such as file name/path/size, then use the same
                # | generator on the box.dlb (box.dlb.files())

        # The box.dlb.files() stay Async even after you import
        # 'tgbox.api.sync', so we need to make it Sync by our
        # hands. This can be done via 'tgbox.api.sync.sync_agen()'
        for dlbf in tgbox.api.sync.sync_agen(box.dlb.files()):
            print(dlbf.id, dlbf.file_name)
                # ^
                # | MUCH faster & doesn't use Remote at all. The
                # | 'box.dlb.get_file()' coro is also available!

        # ----------------------------------------------------------- #

        # ---- search_file() ---------------------------------------- #

        # The TGBOX Protocol support File Searching by
        # filters. For this, we use the SearchFilter
        # class from tgbox.tools. Describing every
        # argument is slightly out of scope here, you
        # are recommended to Read The Docs on Module
        sf = tgbox.tools.SearchFilter(
            mime = 'audio',
            min_id = 100,
            max_id = 200,
            file_path = 'Diary of a Madman',
            scope = '/home/user/Music'
        )
        search_gen = tgbox.api.sync.sync_agen(
            box.dlb.search_file(sf) # | You see, here we use the 'search_file'
        )                           # | directly from the 'box.dlb' because
        for dlbf in search_gen:     # | on the 'box' it will be slow as...
            print(dlbf.file_name)   # | Python programming language??
                # ^
                # | Sure you can use the same method on the 'box',
                # | but it really doesn't make sense for our task

        # ----------------------------------------------------------- #

.. note::
    The TGBOX :doc:`protocol` support *Directories* (see :ref:`How does we store file paths` for information on *how* this implemented). You can get a :class:`~tgbox.api.local.DecryptedLocalBoxDirectory` object via :class:`~tgbox.api.abstract.Box.get_directory` method, load and iterate over it with :class:`~tgbox.api.local.DecryptedLocalBoxDirectory.iterdir`. You can also use the :meth:`~tgbox.api.abstract.Box.contents` generator which behaves like :meth:`~tgbox.api.abstract.Box.files` *but* also returns *Directory* objects.
   | Please read the docs for classes, as examples here will not cover all features of API.

Understanding Files
+++++++++++++++++++

The :class:`~tgbox.api.abstract.BoxFile` is an object that contains all **information** about *original* file that was uploaded to :class:`~tgbox.api.abstract.Box`, as well as method to *Download* it back.

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        lfid = box.get_last_file_id() # Get ID of last uploaded file to Box
        abbf = box.get_file(lfid) # Directly get file by ID

        print(abbf.id) # Get ID of file in Remote
        print(abbf.file_name) # Get Name of file
        print(abbf.size) # Get Size of file
        print(abbf.mime) # Get Mime type of file
        print(abbf.file_path) # Get Path of file

        # BoxFile has 'directory' property, which points
        # to Directory of BoxFile. We can iterate over it
        dir_iterdir = tgbox.api.sync.sync_agen(abbf.directory.iterdir())
        for content in dir_iterdir:
            print(content)

        # BoxFile will have data in the next two properties
        # if FFMPEG was available for the TGBOX Protocol on
        # the file uploading process. 'preview' is raw bytes
        print(abbf.duration) # Get Duration of file (if Media)
        print(abbf.preview) # Get Preview of file (if Media)

        # You can Download your file in the original state by
        # using the simple '.download()' method. It's highly
        # configurable; for example, you can change Path to
        # which file will be downloaded and also specify the
        # file 'offset' if you already downloaded part of it.
        outfile = abbf.download() # Here is just simple download, see
                                  # help() on BoxFile.download

Updating Files & Metadata
+++++++++++++++++++++++++

The :doc:`protocol` support (as far as possible) *File* and *Metadata* updating, for example:

.. code-block:: python

        # "Understanding Files" code was omitted, insert it here ...

        # You can change Name or Path of BoxFile (as well as
        # more little things) with the 'update_metadata()'
        abbf.update_metadata({
            'file_name': b'NonSense.png',
            'file_path': b'/home/non/Pictures'
        })
        # ^
        # | This one call will change file Path to '/home/non/Pictures'
        # | and file Name to 'NonSense.png'. We can NOT change data
        # | of file that was already uploaded to Telegram, so this
        # | changes will be stored in Telegram file caption (sure,
        # | in encrypted form). This has it's own limits, see
        # | docstring on the 'tgbox.api.BoxFile.update_metadata'

        # To "Update" file (for example if you uploaded some text
        # file that has been changed since) we need to make a full
        # re-upload, as Telegram doesn't support (obviously) the
        # partial file change. We can use high-level '.update()'
        # on target file to achieve this.
        pf = box.prepare_file(open('new.txt','rb')) # Prepare new file
        abbf = abbf.update(pf) # Update old file (make re-upload)

        print(abbf) # Show __str__ of updated (with new.txt) BoxFile


Sharing Files
+++++++++++++

.. note::
   On *File Sharing* you will need to give someone else a *FileKey* of your *Box file*. Every file has it's own *FileKey*, so by sharing only one you will give access to specific *Box file* you selected. The *Requester* will be able to decrypt & get all *Metadata* of *file* (except *file_path*, encrypted by *MainKey*). **Proceed only if you understand this**.

Similarly to :ref:`Box Sharing`, every file in *Box* can be shared separately.

I. *(Owner)* **Send target File to your friend**

You need to send to your *friend* a *file* you want to share from your *RemoteBox*. The :doc:`protocol` doesn't have a standardized way to do this, you can make it from the official Telegram clients or via the *Telethon* library (``box.tc`` or ``drb.tc``).

II. *(Friend)* **Get RequestKey for RemoteBox file**

We need to **forward** to our *RemoteBox* the *file* that *file Owner* sent to us, then get a *RequestKey* for it. See code snippet below

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        from tgbox.api.sync import sync_coro

        # After we forwarded target file to our Box we can
        # get its ID with 'get_last_file_id' method on DRB
        lfid = sync_coro(box.drb.get_last_file_id())

        # Get target file as EncryptedRemoteBoxFile object
        erbf = sync_coro(box.drb.get_file(lfid, decrypt=False))

        # Make a RequestKey for target file with our MainKey
        reqkey = sync_coro(erbf.get_requestkey(box.mainkey))

| Now we need to send a *RequestKey* (``reqkey.encode()``) to the *Box file* owner.
| This *Key* **can be shared via insecure communication canals**.

III. *(Owner)* **Make a ShareKey from RequestKey**

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        # Let's imagine that we initially wanted to share
        # (and gave friend) the last file from our Box.
        # Then we use the 'get_last_file_id()'; otherwise,
        # we'd used different ID of target file we share
        lfid = box.get_last_file_id() # ID of file we forwarded
        abbf = box.get_file(lfid) # File that we forwarded

        # Place here RequestKey from your friend
        reqkey = tgbox.keys.Key.decode('R<...>')

        # This is ShareKey. Send it to Requester (your friend)
        shrkey = abbf.get_sharekey(reqkey)

| Now we need to send a *ShareKey* (``shrkey.encode()``) to the *Box file* requester.
| This *Key* **can be shared via insecure communication canals**.

IV. *(Friend)* **Make a ShareKey from RequestKey**

The final step is to get a *ImportKey* and decrypt-then-import target *Box file*

.. code-block:: python

        # Step II. code was omitted, insert it here ...

        # Place here ShareKey from Box owner
        shrkey = tgbox.keys.Key.decode('S<...>')

        # Here we make ImportKey, which is de
        # facto a FileKey of target Box file.
        impkey = tgbox.keys.make_importkey(
            key=box.mainkey,
            sharekey=shrkey,
            salt=erbf.file_salt
        )
        # Decrypt the EncryptedRemoteBoxFile with a ImportKey and
        # finally obtain the DecryptedRemoteBoxFile object
        drbf = sync_coro(erbf.decrypt(key=impkey))

        # Add information about imported DecryptedRemoteBoxFile
        # to our LocalBox with the 'import_file()'. Here, we
        # can specify 'file_path' kwarg to whatever we like,
        # otherwise it will be 'tgbox.defaults.DEF_NO_FOLDER'
        dlbf = box.import_file(drbf, file_path='Imported')

        print(dlbf) # Show __str__ of imported DecryptedLocalBoxFile
        box.done() # Always call it after all work was done.

**File sharing process is done!**

Sharing Directories
+++++++++++++++++++

.. warning::
   On *Directory Sharing* you will need to give someone else a *DirectoryKey*, which is used to **derive** all *File keys* for files in the same *directory*. This means that *Requester* with access to your *RemoteBox* will be able to decrypt **all** of the **past** and **future (!!)** files attached to *directory* of *DirectoryKey*. **Proceed only if you understand this!!**

.. note::
   *DirectoryKey* give access only to specific *Directory*. For example, by sharing *DirectoryKey* of *'/home/user/Pictures'* the *Requester* will be **NOT** able to decrypt files from sub-directories like *'/home/user'* or *'/home/user/Pictures/NonSense'* because they have different *DirectoryKey*.

Similarly to :ref:`Sharing Files`, every directory of files in *Box* can be shared separately (:ref:`Sharing *Box directory*`).

I. *(Owner)* **Send files from the same Directory to your friend**

In order to share a *DirectoryKey* you need to forward to *Requester* at least *one* file that is attached to it. For example, your *Box* have many files in the *'/home/user/Pictures'* directory and you want to give access to **all** *contents* from it to someone else. In this case, see example below

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        from tgbox.api.sync import sync_agen

        # Make a SearchFilter to search *only* in the exact
        # directory with the 'scope' fitler.
        sf = tgbox.tools.SearchFilter(scope='/home/user/Pictures')

        # Extract IDs from the matched DecryptedLocalBox files
        ids = [dlbf.id for dlbf in sync_agen(box.dlb.search_file(sf))]

        # Get from RemoteBox files by extracted IDs
        # and then get '.message' from DRBF objects
        files = list(sync_agen(box.drb.files(ids=ids)))
        files = [drbf.message for drbf in files]

        # Forward all files to specified User
        box.tc.send_message('@username', files)

II. *(Friend)* **Get RequestKey for RemoteBox file**

We need to **forward** to our *RemoteBox* the *files* that *file Owner* sent to us, then get a *RequestKey* for the last one. See code snippet below

.. code-block:: python

        # "Opening Box" code was omitted, insert it here ...

        from tgbox.api.sync import sync_coro

        # After we forwarded target file to our Box we can
        # get its ID with 'get_last_file_id' method on DRB
        lfid = sync_coro(box.drb.get_last_file_id())

        # Get target file as EncryptedRemoteBoxFile object
        erbf = sync_coro(box.drb.get_file(lfid, decrypt=False))

        # Make a RequestKey for target file with our MainKey
        reqkey = sync_coro(erbf.get_requestkey(box.mainkey))
        # ^
        # | Making RequestKey only for one file is
        # | enough to request a DirectoryKey

| Now we need to send a *RequestKey* (``reqkey.encode()``) to the *Box file* owner.
| This *Key* **can be shared via insecure communication canals**.

III. *(Owner)* **Make a ShareKey from RequestKey**

.. code-block:: python

        # Step I. code was omitted, insert it here ...

        from tgbox.api.sync import sync_coro

        # Make a SearchFilter to search *only* in the exact
        # directory with the 'scope' fitler.
        sf = tgbox.tools.SearchFilter(scope='/home/user/Pictures')

        # We need only one file that attached to requested Directory
        # to extract directory from it and make ShareKey
        dlbf = next(sync_agen(box.dlb.search_file(sf)))

        # Place here RequestKey from your friend
        reqkey = tgbox.keys.Key.decode('R<...>')

        # This is ShareKey. Send it to Requester (your friend)
        shrkey = sync_coro(dlbf.directory.get_sharekey(reqkey))

| Now we need to send a *ShareKey* (``shrkey.encode()``) to the *Directory* requester.
| This *Key* **can be shared via insecure communication canals**.

IV. *(Friend)* **Make a ShareKey from RequestKey**

The final step is to get a *ImportKey* and decrypt-then-import target *Box files*

.. code-block:: python

        # Step II. code was omitted, insert it here ...

        from asyncio import gather
        from tgbox.api.sync import sync_agen

        # Place here ShareKey from Box owner
        shrkey = tgbox.keys.Key.decode('S<...>')

        # Here we make ImportKey, which is de
        # facto a DirectoryKey of target Box file.
        impkey = tgbox.keys.make_importkey(
            key=box.mainkey,
            sharekey=shrkey,
            salt=erbf.file_salt
        )

        # Now we have a DirectoryKey in 'impkey'. All we
        # need now is to iterate over DecryptedRemoteBox
        # and import files that we requested
        files_generator = box.drb.files(
            return_imported_as_erbf=True, # | "Imported" files in Remote
            reverse=True                  # |  is a files that have the
        )                                 # | "Forwarded from" header.
        files_to_import = []
        for xrbf in sync_agen(files_generator):
            if isinstance(xrbf, tgbox.api.EncryptedRemoteBoxFile):
                files_to_import.append(xrbf.decrypt(impkey))
                # ^
                # | Here we add coroutines of 'xrbf.decrypt'
                # | to 'files_to_import' to gather them later
            else:
                break # | When 'files_generator' start to return a
                      # | DecryptedRemoteBoxFile objects it probably
                      # | means that we reached all forwarded files

        # Decrypt all files on a Directory with a DirectoryKey
        files_to_import = sync_coro(gather(*files_to_import))

        files_to_import = [
            box.dlb.import_file(drbf)    # | Wrap every DRBF in import_file
            for drbf in files_to_import  # | coro & prepare for gathering
        ]
        # Add information about imported DecryptedRemoteBoxFile
        # to our LocalBox with the 'import_file()' in bunch.
        files_to_import = sync_coro(gather(*files_to_import))

        print(files_to_import) # Show __str__ of list of imported DLBF
        box.done() # Always call it after all work was done.

**Directory sharing process is done!**


The Ol' fashioned Way
---------------------

Here's set of pre-v1.5 examples that doesn't use :mod:`~tgbox.api.abstract` nor :mod:`~tgbox.api.sync` modules at all. By using the :class:`~tgbox.api.local.DecryptedLocalBox` and :class:`~tgbox.api.remote.DecryptedRemoteBox` separately from each other you can gain more flexibility, speed and control over code. Please note that you can write the same code from :ref:`The "Abstract" Module` in Async way, just do not ``import tgbox.api.sync``. If you feel that you lack something from this *Examples*, then check the out :ref:`The "Abstract" Module` firstly, you can easily re-write code to avoid usage of :class:`~tgbox.api.abstract.Box` class.

Logging in & Box creation
+++++++++++++++++++++++++

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

File uploading
++++++++++++++

One upload
^^^^^^^^^^

.. code-block:: python

        from asyncio import run as asyncio_run

        from tgbox.api import get_localbox, get_remotebox
        from tgbox.keys import Phrase, make_basekey

        async def main():
            # Better to use getpass.getpass, but
            # it's can be hard to input passphrase
            # without UI. It's just example, so OK.
            p = Phrase(input('Your Passphrase: '))

            # WARNING: This will use 1GB of RAM for a
            # couple of seconds. See help(make_basekey).
            basekey = make_basekey(p)

            # This will open & decrypt LocalBox
            # on the tgbox.defaults.DEF_TGBOX_NAME
            # path. You can change it with the
            # "tgbox_db_path" keyword argument
            dlb = await get_localbox(basekey)

            # Getting DecryptedRemoteBox
            drb = await get_remotebox(dlb)

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

        asyncio_run(main())

.. tip::
    Using the *LocalBox* instead of the *RemoteBox* is **always** better. Use LocalBox for accessing information about the Box files. Use RemoteBox for downloading them.

.. note::
    For the next examples let's assume that we already have ``DecryptedLocalBox`` (as ``dlb``) & ``DecryptedRemoteBox`` (as ``drb``) to respect `DRY <https://en.wikipedia.org/wiki/Don%27t_repeat_yourself>`_.

Multi-upload
^^^^^^^^^^^^

.. code-block:: python

        from asyncio import gather

        ... # some code was omitted

        # This will upload three files concurrently, wait
        # and return list of DecryptedRemoteBoxFile

        drbf_list = await gather(
            drb.push_file(await dlb.prepare_file(open('cats2.png','rb'))),
            drb.push_file(await dlb.prepare_file(open('cats3.png','rb'))),
            drb.push_file(await dlb.prepare_file(open('cats4.png','rb')))
        )
        for drbf in drbf_list:
            print(drbf.id, drbf.file_name)

.. warning::
    You will receive a 429 (Flood) error and will be restricted for uploading files for some time if you will spam Telegram servers. Vanilla clients allow users to upload 1-3 files per time and no more, however, if you will upload 10 small files at the same time it will be OK.


Iterating
+++++++++

Over files
^^^^^^^^^^

.. code-block:: python

        ... # some code was omitted

        # Iterating over files in RemoteBox
        async for drbf in drb.files():
            print(drbf.id, drbf.file_name)

        # Iterating over files in LocalBox
        async for dlbf in dlb.files():
            print(dlbf.id, dlbf.file_name)


Deep local iteration & Directories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

        ... # some code was omitted

        from tgbox.api import DecryptedLocalBoxFile

        # In this example we will iterate over all
        # asbstract LocalBox contents: Files and Directories

        # To iterate for directories only you can set the
        # ignore_files kwarg to True.

        async for content in dlb.contents(ignore_files=False):
            if isinstance(content, DecryptedLocalBoxFile):
                print('File:', file.id, file.file_name, file.size)
            else:
                await content.lload(full=True) # Load directory path
                print('Dir:', content)

.. note::
    *RemoteBox* doesn't have the ``.contents()`` generator

File search
^^^^^^^^^^^

.. code-block:: python

    ... # some code was omitted

    from tgbox.tools import SearchFilter

    # With this filter, method will search
    # all image files by mime type with a
    # minimum size of 500 kilobytes.

    # See help(SearchFilter) for more
    # keyword arguments and help.
    sf = SearchFilter(mime='image', min_size=500000)

    # Here we search on the LocalBox, but
    # you can also search on the RemoteBox
    async for dlbf in dlb.search_file(sf):
        print(dlbf.id, dlbf.file_name)

Obtain file preview
+++++++++++++++++++

.. code-block:: python

    ... # some code was omitted

    # You can also call this methods on DecryptedRemoteBox,
    # but DecryptedLocalBox is recommend and preferable.

    # Get a last DecryptedLocalBoxFile from LocalBox
    last_dlbf = await dlb.get_file(await dlb.get_last_file_id())

    with open(f'{last_dlbf.file_name}_preview.jpg','wb') as f:
        f.write(last_dlbf.preview)

Changing file metadata
++++++++++++++++++++++

.. code-block:: python

    ... # some code was omitted

    # Get a last DecryptedRemoteBoxFile from RemoteBox
    last_drbf = await drb.get_file(await drb.get_last_file_id())
    #
    # To change metadata you will need to specify DecryptedLocalBox
    #
    # You can also change cattrs, mime and any other
    # metadata fields, not only file path and name.
    #
    await last_drbf.update_metadata(
        changes = {
            'file_name': b'some_nice_filename',
            'file_path':  'some/nice/filepath'
        },
        dlb = dlb # DecryptedLocalBox
    )
    print(last_drbf.file_name) # some_nice_filename
    print(last_drbf.file_path) # some/nice/filepath

.. note::
   You should be able to replace any metadata attribute
   listed in the ``DecryptedLocalBox.__required_metadata``,
   however, changing the ``efile_path`` is **forbidden**.

   Instead of the specifying the ``efile_path`` we
   allow user to specify a ``file_path`` key, which
   is not a part of valid metadata (see :doc:`remotebox`),
   the value should be file path ``str`` or ``pathlib.Path``.

   The user will also need to specify a ``DecryptedLocalBox``
   as ``dlb`` *kwarg*, so we can take a ``MainKey`` from it
   and do all magic encryption-tricks without user involve.

Box clone
+++++++++

.. code-block:: python

    from tgbox.api import (
        TelegramClient,
        get_remotebox,
        clone_remotebox
    )
    from tgbox.keys import make_basekey, Key

    from asyncio import run as asyncio_run
    from getpass import getpass

    # Phone number linked to your Telegram account
    PHONE_NUMBER = '+10000000000'

    # This two is example. Get your own at https://my.telegram.org
    API_ID, API_HASH = 1234567, '00000000000000000000000000000000'

    async def main():
        tc = TelegramClient(
            phone_number = PHONE_NUMBER,
            api_id = API_ID,
            api_hash = API_HASH
        )
        await tc.connect() # Connecting to Telegram
        await tc.send_code() # Requesting login code

        await tc.log_in(
            code = int(input('Code: ')),
            password = getpass('Pass: ')
        )
        # Make decryption key for cloned Box.
        # Please use strength Phrase, we will
        # use it to encrypt your Telegram session.
        # See help(tgbox.keys.Phrase.generate)
        basekey = make_basekey(b'example phrase here')

        # Retrieve RemoteBox by username (entity),
        # you may also use here invite link.
        #
        # In this example we will clone created
        # by Non RemoteBox. MainKey of it is
        # already disclosed. NEVER DISCLOSE
        # keys of your private Boxes. If you
        # want to share Box with someone
        # else, use ShareKey. See docs.
        #
        # Retrieving MainKey will give
        # FULL R/O ACCESS to your box.
        erb = await get_remotebox(tc=tc, entity='@nontgbox_non')

        # Disclosed MainKey of the @nontgbox_non
        # RemoteBox. See t.me/nontgbox_non/67
        mainkey = 'MbxTyN4T2hzq4sb90YSfWB4uFtL03aIJjiITNUyTqdoU='
        mainkey = Key.decode(mainkey) # Will decode to MainKey

        # Wrap and decrypt @nontgbox_non
        drb = await erb.decrypt(key=mainkey)
        # Clone and retrieve DecryptedLocalBox
        dlb = await clone_remotebox(drb, basekey)

        # Iterate over DecryptedLocalBox contents
        async for content in dlb.contents(ignore_files=False):
            if isinstance(content, DecryptedLocalBoxFile):
                print('File:', file.id, file.file_name, file.size)
            else:
                await content.lload(full=True) # Load directory path
                print('Dir:', content)

        await dlb.done()
        await drb.done()

    asyncio_run(main())

Accessing Telegram methods
++++++++++++++++++++++++++

As TGBOX built on `Telethon <https://github.com/LonamiWebs/Telethon>`_, you can access full power of this beautiful library. The ``tgbox.api.TelegramClient`` inherits from the ``telethon.TelegramClient`` and supports all of its features, adding a little more.

.. code-block:: python

    ... # some code was omitted

    # You can get TelegramClient object from the
    # *RemoteBox or even from the *RemoteBoxFile

    me = await drb.tc.get_me() # Getting your account
    print(me.first_name, me.id) # Printing base info

    lfid = await drb.get_last_file_id() # Getting last RemoteBoxFile ID
    drbf = await drb.get_file(lfid) # Getting last file by ID

    # Sending message to your SavedMessages chat from
    # the DecryptedRemoteBoxFile -> tc method
    await drbf.tc.send_message('me','Hello from TGBOX!')

.. tip::
    - See `Telethon documentation <https://docs.telethon.dev/>`_.
    - You can find a ``TelegramClient`` object in the ``tc`` property.

Examples
========

Logging in & Box creation
-------------------------

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
--------------

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
---------

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
-------------------

.. code-block:: python

    ... # some code was omitted

    # You can also call this methods on DecryptedRemoteBox,
    # but DecryptedLocalBox is recommend and preferable.

    # Get a last DecryptedLocalBoxFile from LocalBox
    last_dlbf = await dlb.get_file(await dlb.get_last_file_id())

    with open(f'{last_dlbf.file_name}_preview.jpg','wb') as f:
        f.write(last_dlbf.preview)

Changing file metadata
----------------------

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
---------

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
--------------------------

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

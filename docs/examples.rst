Examples
========

Logging in & Box creation
-------------------------

.. code-block:: python

        from tgbox.api import (
            TelegramClient, 
            make_remote_box,
            make_local_box
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
            erb = await make_remote_box(tc)
            # Make DecryptedLocalBox
            dlb = await make_local_box(erb, basekey)
            
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
            print('File name:', drbf.file_name.decode())

            # You can also access all information about
            # the RemoteBoxFile you need from the LocalBox
            dlbf = await dlb.get_file(drb.id)

            print('File path:', dlbf.file_path)
            print('Custom Attributes:', dlbf.cattrs)

            # Downloading file back.
            await drbf.download()

            # Close all connections
            # after work was done
            await erb.done()
            await dlb.done()
        
        asyncio_run(main())

File uploading 
--------------

One upload
^^^^^^^^^^

.. code-block:: python
        
        from asyncio import run as asyncio_run
        from tgbox.api import get_local_box, get_remote_box
        from tgbox.keys import Phrase, make_basekey


        async def main():
            # Better to use getpass.getpass, but
            # it's can be hard to input passphrase 
            # without UI. It's just example, so OK.
            p = Phrase(input('Your Passphrase: '))

            # WARNING: This will use 1GB of RAM for a
            # couple of seconds. See help(make_basekey).
            basekey = make_basekey(p)

            # Opening & decrypting LocalBox. You
            # can also specify MainKey instead BaseKey
            dlb = await get_local_box(basekey)

            # Getting DecryptedRemoteBox
            drb = await get_remote_box(dlb)
            
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
            print('File name:', drbf.file_name.decode())

            # You can also access all information about
            # the RemoteBoxFile you need from the LocalBox
            dlbf = await dlb.get_file(drb.id)

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
    You will receive a 429 (Flood) error and will be restricted for uploading files for some time if you will spam Telegram servers. Vanilla clients allow users to upload 1-3 files per time and no more, however, if you will upload 10 small files at the same time it will be OK, but if you will upload even three big files similarly then you almost guarantee to get a flood error. 


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
                print('Dir:', content, content.part_id.hex())

.. note::
    *RemoteBox* doesn't have the ``.contents()`` generator


Download file preview
---------------------

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

   This behaviour is because of the first "e" letter,
   it stands for word "encrypted" , so users should have
   to manually encrypt its file path with the ``MainKey``
   and only after specify it in ``changes`` dict. As
   you may see this is a totally discouraged.

   Instead of the specifying the ``efile_path`` we
   allow user to specify a ``file_path`` key, which
   is not a part of valid metadata (see :doc:`remotebox`),
   the value should be file path ``str`` or ``pathlib.Path``.

   The user will also need to specify a ``DecryptedLocalBox``
   as ``dlb`` *kwarg*, so we can take a ``MainKey`` from it
   and do all magic tricks without user involve.

   As per v1.0 this works only for ``file_path``.

File search
-----------

.. code-block:: python
        
    ... # some code was omitted
    
    from tgbox.tools import SearchFilter
    
    # With this filter, method will search
    # all image files by mime with a minimum
    # size of 500 kilobytes. 

    # See help(SearchFilter) for more
    # keyword arguments and help.

    sf = SearchFilter(mime='image/', min_size=500000)

    # You can also search on RemoteBox
    async for dlbf in dlb.search_file(ff):
        print(dlbf.id, dlbf.file_name)

Box clone
---------

.. code-block:: python

    from tgbox.api import TelegramClient, get_remote_box
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
        await tc.connect() # Connecting with Telegram
        await tc.send_code() # Requesting login code

        await tc.log_in(
            code = int(input('Code: ')),
            password = getpass('Pass: ')
        )
        # Make decryption key for cloned Box.
        # Please, use strength Phrase, we
        # encrypt with it your Telegram session.
        # See keys.Phrase.generate method.
        basekey = make_basekey(b'example phrase here')

        # Retreive RemoteBox by username (entity),
        # you may also use here invite link.
        # 
        # In this example we will clone created
        # by Non RemoteBox. MainKey of it is
        # already disclosed. NEVER DISCLOSE
        # keys of your private Boxes. If you
        # want to share Box with someone
        # else, use ShareKey. See docs.
        #
        # Retreiving MainKey will give
        # FULL R/O ACCESS to your files.
        erb = await get_remote_box(tc=tc, entity='@nontgbox_non')

        # Disclosed MainKey of the @nontgbox_non
        # RemoteBox. See t.me/nontgbox_non/67
        mainkey = Key.decode(
            'MbxTyN4T2hzq4sb90YSfWB4uFtL03aIJjiITNUyTqdoU='
        )
        # Decrypt @nontgbox_non
        drb = await erb.decrypt(key=mainkey)
        # Clone and retreive DecryptedLocalBox
        dlb = await drb.clone(basekey)

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
    drbf = await drb.get_file(drb.last_file_id()) # Getting last file by ID
    
    # Sending message to your SavedMessages chat!
    await drbf.tc.send_message('me','Hello from TGBOX!')

.. tip::
    - See a `Telethon documentation <https://docs.telethon.dev/>`_.
    - You can find a ``TelegramClient`` object in the ``tc`` property

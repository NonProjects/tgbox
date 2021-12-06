Examples
========

Logging in & Box creation
-------------------------

.. code-block:: python

        # This is global Tgbox loop.
        # You should use it if you
        # want to add coroutines to
        # the event loop.
        from tgbox import loop

        from tgbox.api import (
            TelegramAccount, 
            make_remote_box,
            make_local_box
        )
        from tgbox.keys import Phrase, make_basekey
        from getpass import getpass # For hidden input


        async def main():
            ta = TelegramAccount(
                phone_number = input('Phone: ')
            )
            await ta.connect()
            await ta.send_code_request()

            await ta.sign_in(
                code = int(input('Code: ')),
                password = getpass('Pass: ')
            )
            # Generate passphrase.
            p = Phrase.generate()
            print(p.phrase, '<- your phrase')
            
            # WARNING: This will use 1GB of RAM for a
            # couple of seconds. See help(make_basekey).
            basekey = make_basekey(p)

            # Make EncryptedRemoteBox
            erb = await make_remote_box(ta)
            # Make DecryptedLocalBox
            dlb = await make_local_box(rb, ta, basekey)

        loop.run_until_complete(main()) 


File uploading 
--------------

Synchronous
^^^^^^^^^^^

.. code-block:: python
        
        from tgbox import loop
        from tgbox.api import get_local_box, get_remote_box
        from tgbox.keys import Phrase, make_basekey


        async def main():
            # Better to use getpass.getpass, but
            # it's can be hard to input passphrase 
            # without UI. It's just example, so OK.
            p = Phrase(input('@ Phrase: '))
            # WARNING: This will use 1GB of RAM for a
            # couple of seconds. See help(make_basekey).
            basekey = make_basekey(p)
            # Opening & decrypting LocalBox. 
            # You can also specify MainKey.
            dlb = await get_local_box(basekey)
            # Getting DecryptedRemoteBox
            drb = await get_remote_box(dlb)
            # Making upload file, returns FutureFile
            ff = await dlb.make_file(
                file = open('cats.png','rb'),
                comment = b'Cats are cool B-)',
                foldername = b'Pictures/Kitties' 
            )
            # Uploading FutureFile to the RemoteBox
            # return DecryptedRemoteBoxFile
            drbfi = await drb.push_file(ff)

            # Retrieving some RemoteBoxFile info
            print('Size:', drbfi.size)
            print('File name:', drbfi.file_name)
            print('Folder:', drbfi.foldername)
            print('Comment:', drbfi.comment)
            
            # Download it back.
            await drbfi.download()

        loop.run_until_complete(main())

.. note::
    For the next examples let's assume that we already have ``DecryptedLocalBox`` (as ``dlb``) & ``DecryptedRemoteBox`` (as ``drb``) to respect `DRY <https://en.wikipedia.org/wiki/Don%27t_repeat_yourself>`_.

Asynchronous
^^^^^^^^^^^^

.. code-block:: python
        
        # We use gather() here, but 
        # there is also tgbox.loop.create_task
        from asyncio import gather

        ... # some code omitted
        
        # This will upload three files
        # concurrently, wait and return
        # list of DecryptedRemoteBoxFile
        drbfi_list = await gather(
            drb.push_file(await dlb.make_file(open('cats1.png','rb'))),
            drb.push_file(await dlb.make_file(open('cats2.png','rb'))),
            drb.push_file(await dlb.make_file(open('cats3.png','rb')))
        )

.. warning::
    I don't know how it will affect your Telegram account, as official clients allow one or two uploads at the same time. Your account or session may be restricted for file uploading, or **even blocked** (not sure). Be careful, and not spam servers. It's not well tested as per `1.0` version.


Iterating 
---------

Over files
^^^^^^^^^^

.. code-block:: python
        
        ... # some code omitted

        # Iterating over files in RemoteBox
        async for drbfi in drb.files():
            print(drbfi.id, drbfi.file_name)

        # Iterating over files in LocalBox
        async for dlbfi in dlb.files():
            print(dlbfi.id, dlbfi.file_name)


Over folders
^^^^^^^^^^^^

.. code-block:: python
        
        ... # some code omitted

        # Iterating over folders in LocalBox
        async for lbf dlb.folders():
            print(lbf.dec_foldername)
            # Iterating over files in Folder
            async for dlbfi in lbf.files():
                print(dlbfi.id, dlbfi.file_name)

.. note::
    *RemoteBox* doesn't have abstract *Folder* class, so only *LocalBox*.


Download file preview
---------------------

.. code-block:: python
        
    # You can also call this methods on DecryptedLocalBox.
    ... # some code omitted

    last_drbfi = await drb.get_file(dlb.last_file_id)
    with open(f'{last_drbfi.file_name}_preview.jpg', 'wb') as f:
        f.write(await last_drbfi.get_preview())


File search
-----------

.. code-block:: python
        
    ... # some code omitted
    
    from tgbox.tools import SearchFilter
    
    # With this filter, method will search
    # all files that have .jpg or .png in
    # name, Pictures in foldername and
    # 1MB minimum size.

    # There is also `re` kwarg, it
    # tell search method that every
    # bytestring is Regular Expression.

    # See help(SearchFilter) for more
    # keyword arguments.

    sf = SearchFilter(
        file_name = [b'.jpg', b'.png'],
        folder = b'Pictures',
        min_size = 1e+6
    )
    # You can also search on RemoteBox
    async for dlbfi in dlb.search_file(ff):
        print(dlbfi.id, dlbfi.file_name)


Telethon
--------

As Tgbox built on `Telethon <https://github.com/LonamiWebs/Telethon>`_, you can access full power of this beautiful library.

.. code-block:: python
        
    ... # some code omitted
    
    my_account = await drb._ta.TelegramClient.get_me()
    print(my_account.first_name, my_account.id) 

- See `TelegramClient documentation <https://docs.telethon.dev/en/latest/modules/client.html>`_.

RemoteBox
=========

The *RemoteBox* is a place where we store encrypted files. It's a Telegram ``Channel``, that have encoded by url safe Base64 *BoxSalt* in the description. By default, all created by API channels will have ``f"TGBOX[{VERBYTE.hex()}]: "`` prefix in the name.

RemoteBox file
--------------

The ``EncryptedRemoteBoxFile`` has own metadata. As per **version 1** schema looks like follows:

.. image:: images/rbfm_schema.png

To decrypt file's attributes, we need to go through some steps:

0. Sum length of ``PREFIX``, ``VERBYTE`` and ``METADA_SIZE`` (*10 by default*), get a ``fixed_bytes_size``
1. Download fixed bytes: ``from=0``, ``to=fixed_bytes_size``; get a ``PREFIX``, ``VERBYTE`` and ``METADA_SIZE``
2. Convert ``METADA_SIZE`` to ``int`` and verify that ``METADATA_SIZE <= defaults.Limits.METADATA_MAX``
3. Download the metadata: ``from=fixed_bytes_size``, ``to=METADA_SIZE``, receive a ``metadata``
4. Unpack ``metadata`` with the ``tools.PackedAttributes.unpack(metadata)``, receive a ``metadata_dict``
5. If ``BaseKey`` isn't presented, take a user's password/phrase and call ``keys.make_basekey(phrase)``
6. If ``MainKey`` isn't presented, take a user's ``basekey`` and call ``keys.make_mainkey(basekey, metadata_dict['box_salt'])``
7. If ``FileKey`` isn't presented, take a user's ``mainkey`` and call ``keys.make_filekey(mainkey, metadata_dict['file_salt'])``
8. Decrypt ``metadata_dict['secret_metadata']`` with the user's ``filekey``
9. Unpack ``secret_metadata`` with the ``tools.PackedAttributes.unpack(secret_metadata)``
10. If ``MainKey`` was presented, decrypt ``secret_metadata['efile_path']``, get a ``file_path``

.. note::
    - Unpacked *metadata* is a ``{'box_salt': ..., 'file_salt': ..., 'file_fingerprint': ..., 'secret_metadata': ...}``;
    - ``file_fingerprint`` is a hash of the *file_path* plus ``MainKey``, **not a hash of file**;
    - We need to decrypt *secret_metadata* with the ``FileKey`` and unpack it to access attributes;
    - We **always** encrypt *efile_path* attribute with the ``MainKey``;
    - Max bytesize of *metadata* is defined in the ``defaults.Limits.METADATA_MAX`` variable;
    - *RemoteBox* Telegram channel **doesn't** store any sensitive information. You can leave it public if you want but beware, if you're using weak or predictable password then you can still be brute-forced;
    - *RemoteBox* store all information that store :doc:`localbox`.

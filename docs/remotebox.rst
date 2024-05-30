RemoteBox
=========

The **RemoteBox** is a *Telegram Channel* and a place where we store *Metadata* **plus** *Encrypted Files*. *RemoteBox* stores encoded by `Url Safe Base64 <https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode>`_ :class:`~tgbox.crypto.BoxSalt` in the description. By default, all created by :doc:`protocol` *Telegram Channels* will have a ``f"TGBOX[{tgbox.defaults.VERBYTE.hex()}]: "`` prefix in the *name*.

.. versionadded:: v1.5
    Now users can **add their description** about *Box* in a format "*My optional Description! @ <BOX_SALT>*". I.e: *My text @ amiBJVgXyJ9akLHSZV7T8hvcTmRpKvr9LhvY9WiTU18=*. **From your code**, you can easily fetch it via :meth:`~tgbox.api.remote.DecryptedRemoteBox.get_box_description` method.

| Currently, the *RemoteBox* doesn't really have any special things to discuss here.
| We use it only to store a *Files* produced by the :doc:`protocol`.

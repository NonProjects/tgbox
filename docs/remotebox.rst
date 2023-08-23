RemoteBox
=========

The **RemoteBox** is a *Telegram Channel* and a place where we store *Encrypted Files* **plus** *Metadata*. *RemoteBox* store encoded by `Url Safe Base64 <https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode>`_ :class:`~tgbox.crypto.BoxSalt` in the description. By default, all created by :doc:`protocol` *Telegram Channels* will have a ``f"TGBOX[{tgbox.defaults.VERBYTE.hex()}]: "`` prefix in the *name*.

| Currently, the *RemoteBox* doesn't really have any special things to discuss here.
| It's used only to store a *Files* produced by the :doc:`protocol`.

TGBOX: encrypted cloud storage based on Telegram API
====================================================

Motivation
----------

The Telegram is beautiful app. Not only by mean of features and Client API, but it's also good in cryptography and secure messaging. In the last years, core and client devs of Telegram mostly work for "social-network features", i.e video chats and message reactions, which is OK, but there also can be plenty of "crypto-related" things. Library target to be a PoC of **encrypted file storage**, but can be used as standalone API.

Abstract
--------

We name *"encrypted cloud storage"* as **Box** and the API to it as **Tgbox**. There is **two** of boxes: the **RemoteBox** and the **LocalBox**. They define a basic primitives. You can share your Box and separate Files with other people absolutely secure - only You and someone you want will have decryption key, even through insecure communication canals (`e2e <https://en.wikipedia.org/wiki/End-to-end_encryption>`_). You can make unlimited amount of Boxes, upload speed equals to vanilla Telegram and maximum filesize is ``~2GB-2MB``.


.. toctree::
   :maxdepth: 2
   :caption: Core:
   
   installation
   basis
   remotebox
   localbox
   examples

.. toctree::
   :maxdepth: 2
   :caption: Modules:

   tgbox

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

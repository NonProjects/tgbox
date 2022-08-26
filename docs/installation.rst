Installation
============

PyPI (pip)
----------

.. code-block:: console

   python3 -m pip install tgbox # Pure Python (very slow)
   python3 -m pip install tgbox[fast] # With C libraries

Clone from GitHub
-----------------

.. code-block:: console
   
   # You can replace --branch=indev with --branch=main
   git clone https://github.com/NonProjects/tgbox --branch=indev
   python3 -m pip install ./tgbox/[fast]

Optional dependencies
---------------------

- Library can work without ``pycryptodome``, with ``pyaes``, but this will be **much** slower.
- `ECDSA <https://github.com/tlsfuzzer/python-ecdsa>`_ will be faster with ``gmpy2``. You can install it with `pip <https://pip.pypa.io/en/stable/installation/>`_.
- `Telethon <https://github.com/LonamiWebs/Telethon>`_ may need `LibSSL <https://github.com/openssl/openssl>`_ to work faster. 
- With `FFmpeg <https://ffmpeg.org/download.html>`_ library can make previews for media files and extract duration to attach it to the *RemoteBoxFile*.


Install last updates to the Telethon
------------------------------------

.. warning::
   By default (on ``pip install tgbox``) we download ``telethon`` from the PyPi, but this package on PyPi is often **outdated** and can not support new Telegram features (like sending 4GB files), this can throw you in some strange errors. You recommended to install the Telethon separately, from the v1.24 branch, official GitHub page. Please make sure to **check last commits** before you install from GitHub! The release of the ``telethon`` on PyPi is static, so it's always safe-to-install. GitHub branch is dynamic, so there is a **really little chance** that it will be attacked by some bad commits and your Telegram account will be compromised. A **very little chance**, but **not** zero.

.. code-block:: console
   
   # (Way 1) You can reinstall it on every new huge update on GitHub
   pip install https://github.com/LonamiWebs/Telethon/archive/v1.24.zip

   # (Way 2) You can install it after cloning from GitHub
   git clone https://github.com/LonamiWebs/Telethon/ --branch v1.24
   pip install ./Telethon # local install from cloned repository

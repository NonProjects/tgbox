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

- Library can work without `cryptography <https://github.com/pyca/cryptography>`_, with ``pyaes`` and ``ecdsa`` but this will be **much** slower and **not** so secure. Pure Python is **not recommended** for use by end-users, but test-only is OK!
- With `FFmpeg <https://ffmpeg.org/download.html>`_ library can make previews for media files and extract duration to attach it to the *RemoteBoxFile*. You should add it to your system's ``PATH``, (if the OS didn't do it for you) we will call it as ``ffmpeg`` (``tgbox.defaults.FFMPEG``) via ``subprocess``.


Install last Telethon updates
-----------------------------

.. note::
   Updates for v1.24 was released on PyPi as *v1.25.0* at Aug 30, 2022. We already include it in our requirements, so you may **ignore** this chapter if this version is enough for you.

By default (on ``pip install tgbox``) we download ``telethon`` from the PyPi, but this package on PyPi is often **outdated** and can not support new Telegram features (like sending 4GB files [before v1.25]), this can throw you in some strange errors. You recommended to install the Telethon separately, from the v1.24 branch, official GitHub page.

.. warning::
   Please make sure to **check last commits** before you install from GitHub! The release of the ``telethon`` on PyPi is static, so it's always safe-to-install. GitHub branch is dynamic, so there is a **really little chance** that it will be attacked by some bad commits and your Telegram account will be compromised. A **very little chance**, but **not** zero.

.. code-block:: console
   
   # (Way 1: PIP) You can reinstall it on every new huge update on GitHub
   pip install https://github.com/LonamiWebs/Telethon/archive/v1.24.zip

   # (Way 2: GIT) You can install it after cloning from GitHub
   git clone https://github.com/LonamiWebs/Telethon/ --branch v1.24
   pip install ./Telethon # local install from cloned repository

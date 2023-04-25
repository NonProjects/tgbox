Installation
============

.. note::
    TGBOX library require `Python <https://www.python.org/downloads>`_ version **3.8 or above**.

PyPI (pip)
----------

.. code-block:: console

   python3 -m pip install tgbox # Pure Python (very slow)
   python3 -m pip install tgbox[fast] # With C libraries

Clone from GitHub
-----------------

.. code-block:: console

   # You can replace --branch=main with --branch=indev
   git clone https://github.com/NonProjects/tgbox --branch=main
   python3 -m pip install ./tgbox/[fast]

Optional dependencies
---------------------

- Library can work without `cryptography <https://github.com/pyca/cryptography>`_, with ``pyaes`` and ``ecdsa`` but this will be **much** slower and **not** so secure. Pure Python is **not recommended** for use by end-users, but test-only is OK!
- With `FFmpeg <https://ffmpeg.org/download.html>`_ library can make previews for media files and extract duration to attach it to the *RemoteBoxFile*. You should add it to your system's ``PATH``, (if the OS didn't do it for you) we will call it as ``ffmpeg`` (``tgbox.defaults.FFMPEG``) via ``subprocess``.

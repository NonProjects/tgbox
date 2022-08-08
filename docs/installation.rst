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
   
   # You can replace --branch=main with --branch=indev
   git clone https://github.com/NonProjects/tgbox --branch=main
   python3 -m pip install ./tgbox/[fast]

Optional dependencies
---------------------

- Library can work without ``pycryptodome``, with ``pyaes``, but this will be **much** slower.
- `ECDSA <https://github.com/tlsfuzzer/python-ecdsa>`_ will be faster with ``gmpy2``. You can install it with `pip <https://pip.pypa.io/en/stable/installation/>`_.
- `Telethon <https://github.com/LonamiWebs/Telethon>`_ may need `LibSSL <https://github.com/openssl/openssl>`_ to work faster. 
- With `FFmpeg <https://ffmpeg.org/download.html>`_ library can make previews for media files and extract duration to attach it to the *RemoteBoxFile*.

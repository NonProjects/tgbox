Installation
============

PyPI (pip)
----------

.. code-block:: console

   python3 -m pip install tgbox


Clone from GitHub
-----------------

.. code-block:: console

   git clone https://github.com/NonProject/tgbox
   cd tgbox; python3 -m pip install -r requirements.txt

Optional dependencies
--------------------

- Library can work without ``pycryptodome``, with ``pyaes``, but this will be **much** slower.
- `ECDSA <https://github.com/tlsfuzzer/python-ecdsa>`_ will be faster with ``gmpy2``. You can install it with `pip <https://pip.pypa.io/en/stable/installation/>`_.
- `Telethon <https://github.com/LonamiWebs/Telethon>`_ may need `LibSSL <https://github.com/openssl/openssl>`_ to work faster. 
- With `FFmpeg <https://ffmpeg.org/download.html>`_ library can make previews for media files and extract duration to attach it to the *RemoteBoxFile*.

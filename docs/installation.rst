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
- Library will be a bit faster with ``gmpy2``.

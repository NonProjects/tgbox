Installation
============

.. note::
    TGBOX library **require** `Python <https://www.python.org/downloads>`_ version **3.8 or above**.

PyPI (pip)
----------

.. code-block:: console

   python3 -m pip install tgbox # Pure Python (very slow)
   python3 -m pip install tgbox[fast] # With C libraries

Clone from GitHub
-----------------

.. code-block:: console

   git clone https://github.com/NonProjects/tgbox
   python3 -m pip install ./tgbox/[fast]

Optional dependencies
---------------------

- Library can work in a **Pure Python** way, without `cryptography <https://github.com/pyca/cryptography>`_, by using `pyaes <https://pypi.org/project/pyaes>`_ and `ecdsa <https://pypi.org/project/ecdsa>`_ only, but this will be **much slower** and **not so secure**. Pure Python is **not recommended** for use, but testing only is OK!

- With `FFmpeg <https://ffmpeg.org/download.html>`_, library can **make previews** for media files and **extract duration** to attach it to the *RemoteBox File*. To work, it should be in your System ``PATH`` (`see more about PATH <https://en.wikipedia.org/wiki/PATH_(variable)>`_). We will call it as ``ffmpeg`` (:const:`tgbox.defaults.FFMPEG`) shell command via `subprocess <https://docs.python.org/3/library/subprocess.html>`_.

.. note::
   The `cryptography <https://github.com/pyca/cryptography>`_ project has `wheels <https://packaging.python.org/en/latest/glossary/#term-Wheel>`_ for many systems. Big chance that you **will not need to compile a C code**, so always try to install ``tgbox[fast]``.

"""
This (slightly changed module & its features) was taken from the Telethon
library made by Lonami under MIT License: github.com/LonamiWebs/Telethon

Parts of this file i moved to the tgbox.api.utils package module, check
the out _syncify_wrap() and syncify functions. They are NOT mine.

Thanks to the Lonami. See part of the original description:

--->
This magical module will rewrite all public methods in the public interface
of the library so they can run the loop on their own if it's not already
running. This rewrite may not be desirable if the end user always uses the
methods they way they should be ran, but it's incredibly useful for quick
scripts and the runtime overhead is relatively low.<---

All you should do is to firstly import this module, then anything you want.
"""

import logging

from . import local
from . import remote
from . import abstract

from .local import (
    EncryptedLocalBoxDirectory,
    DecryptedLocalBoxDirectory
)
from .abstract import Box, BoxFile
from .utils import TelegramClient, syncify

__all__ = []

logger = logging.getLogger(__name__)

syncify(
    Box, BoxFile, TelegramClient,
    local, remote, abstract,

    EncryptedLocalBoxDirectory,
    DecryptedLocalBoxDirectory
)
# We inherit some methods from the parent classes
# on __init__ in the 'abstract' module. We did not
# sync this methods here, so we will need to sync
# it additionally later. This flags will help us.
Box._needs_syncify = True # pylint: disable=W0212
BoxFile._needs_syncify = True # pylint: disable=W0212

# We import classes and functions from the abstract.py module
# in __init__.py (.) so they can be accessed via the
# from 'tgbox.api import Box' (e.g). As this import comes
# before the user imports 'tgbox.api.sync', __init__.py
# caches the Async versions of this functions. So, for
# example, after 'import tgbox.api.sync' the functions
# or classes in __init__.py (get_box, Box, etc) will
# stay the same, but in abstract.py they will be synced.
#
# from tgbox.api import get_box <-- Will stay Async
# from tgbox.api.abstract import get_box <-- Will become Sync
#
# This is a strange behaviour and below we fix it by
# updating __dict__ of the __init__.py with synced
# versions of classes/functions. A bit quirky way,
# but will resolve our issue.
from .abstract import (
    __dict__ as abstract__dict__,
    __all__ as abstract__all__
)
from . import __dict__ as root__dict__

for k,v in root__dict__.items():
    # We update only things that presented in both
    # modules AND in tgbox.api.abstract.__all__
    if k in abstract__dict__ and k in abstract__all__:
        logger.debug('__init__.%s was updated!' % k)
        root__dict__[k] = abstract__dict__[k]

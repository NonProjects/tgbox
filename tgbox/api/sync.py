"""
This (slightly changed module & its features) was taken from the Telethon
library made by Lonami under MIT License: github.com/LonamiWebs/Telethon

Parts of this file i moved to the tgbox.api.utils package module, check
the out _syncify_wrap_func() and syncify functions. They are NOT mine.

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

from typing import AsyncGenerator

from . import local
from . import remote
from . import abstract

from .abstract import Box, BoxFile
from .utils import TelegramClient, syncify

from ..tools import anext
from .. import sync as sync_coro

__all__ = ['sync_agen', 'sync_coro']

logger = logging.getLogger(__name__)

def sync_agen(async_gen: AsyncGenerator):
    """
    This will make async generator to sync
    generator, so we can write "for" loop.

    Use this functions on generators that
    you want to syncify. For example, if
    you want to iterate over LocalBox in
    sync code (to load *only* local files):

    .. code-block:: python

        ... # Some code was omited

        async_gen = box.dlb.files(reverse=True)
        for dlbf in tgbox.api.sync.sync_agen(async_gen):
            print(dlbf.id, dlbf.file_name, dlbf.size)

    .. tip::
        To sync coroutines you can use a ``sync`` func
        from the tgbox package (`tgbox.sync`) or use
        it from here as `tgbox.api.sync.sync_coro`
    """
    try:
        while True:
            yield sync_coro(anext(async_gen))
    except StopAsyncIteration:
        return

syncify(
    Box, BoxFile, TelegramClient,
    local, remote, abstract
)
# We inherit some methods from the parent classes
# on __init__ in the 'abstract' module. We did not
# sync this methods here, so we will need to sync
# it additionally later. This flags will help us.
Box._needs_syncify = True # pylint: disable=W0212
BoxFile._needs_syncify = True # pylint: disable=W0212

# We import classes and functions from the 'api' package
# in __init__.py (.) so they can be accessed via the
# from 'tgbox.api import Box' (e.g). As this import comes
# before the user imports 'tgbox.api.sync', __init__.py
# caches the Async versions of this functions. So, for
# example, after 'import tgbox.api.sync' the functions
# or classes in __init__.py (get_box, Box, etc) will
# stay the same, but in 'api' they will be synced.
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
from .local import (
    __dict__ as local__dict__,
    __all__ as local__all__
)
from .remote import (
    __dict__ as remote__dict__,
    __all__ as remote__all__
)
from . import __dict__ as root__dict__

__dict_to_update = (
    (abstract__dict__, abstract__all__),
    (local__dict__, local__all__),
    (remote__dict__, remote__all__)
)
for x__dict__, x__all__ in __dict_to_update:
    for k,v in root__dict__.items():
        # We update only things that presented in both
        # modules (sync & x) AND in x__all__
        if k in x__dict__ and k in x__all__:
            logger.debug('__init__.%s was updated!' % k)
            root__dict__[k] = x__dict__[k]

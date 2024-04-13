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

from . import local
from . import remote
from . import abstract

from .local import (
    EncryptedLocalBoxDirectory,
    DecryptedLocalBoxDirectory
)
from .abstract import Box, BoxFile
from .utils import TelegramClient, syncify

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

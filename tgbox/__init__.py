__version__ = '0.4'

from asyncio import get_event_loop
from typing import Coroutine

from . import api
from . import constants
from . import crypto
from . import db
from . import errors
from . import keys
from . import tools


__all__ = [
    'api',
    'constants',
    'crypto',
    'db',
    'errors',
    'keys',
    'tools',
    'sync',
]
def sync(coroutine: Coroutine):
    """
    Will call asynchronous function in
    current asyncio loop and return result.
    """
    loop = get_event_loop()
    return loop.run_until_complete(coroutine)

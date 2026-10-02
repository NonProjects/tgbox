"""
Encrypted cloud storage API based on Telegram
https://github.com/NonProjects/tgbox
"""

__author__ = 'https://github.com/NonProjects'
__maintainer__ = 'https://github.com/NotStatilko'
__email__ = 'thenonproton@pm.me'

__copyright__ = 'Copyright 2026, NonProjects'
__license__ = 'LGPL-2.1'

__all__ = [
    'api',
    'defaults',
    'crypto',
    'errors',
    'keys',
    'tools',
    'sync'
]
import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

import sys

# This function will auto-log all unhandled exceptions
def log_excepthook(exc_type, exc_value, exc_traceback):
    # I don't think we should log KeyboardInterrupt
    if not issubclass(exc_type, KeyboardInterrupt):
        logger.critical(
            'Found Critical error! See Traceback below:',
            exc_info=(exc_type, exc_value, exc_traceback)
        )
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

sys.excepthook = log_excepthook

from typing import Coroutine

from . import api
from . import defaults
from . import crypto
from . import errors
from . import keys
from . import tools

__version__ = defaults.VERSION


def sync(coroutine: Coroutine, create_task: bool=False):
    """
    Will call async coro in event loop and return result.

    If ``create_task`` is ``True``, will call ``create_task()``
    on loop and return ``Future``. Otherwise will call
    ``run_until_complete()`` on your coro and return result.

    DO NOT use this helper INSIDE async coroutine. The only
    point of this function is turn some tgbox async coros
    into blocking sync funcs. Inside async def, just use
    the async methods and await them.
    """
    if defaults._LOOP is None:
        try:
            from uvloop import new_event_loop
            defaults._LOOP = new_event_loop()
            logger.debug('Uvloop is installed and available. We will use it!')
        except (ImportError, ModuleNotFoundError):
            from asyncio import new_event_loop
            defaults._LOOP = new_event_loop()
            logger.debug('Uvloop is not installed or not supported')

    if create_task:
        return defaults._LOOP.create_task(coroutine)
    else:
        return defaults._LOOP.run_until_complete(coroutine)

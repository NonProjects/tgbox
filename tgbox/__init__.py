"""
Encrypted cloud storage API based on Telegram
https://github.com/NonProjects/tgbox
"""
__version__ = '1.2+indev'

__author__ = 'https://github.com/NonProjects'
__maintainer__ = 'https://github.com/NotStatilko'
__email__ = 'thenonproton@pm.me'

__copyright__ = 'Copyright 2023, NonProjects'
__license__ = 'LGPL-2.1'

__all__ = [
    'api',
    'defaults',
    'crypto',
    'errors',
    'keys',
    'tools',
    'sync',
]
import logging

logging.basicConfig(
    format = (
        ''':%(asctime)s: %(levelname)s:%(name)s~'''
        '''%(funcName)s{%(lineno)s} ::: %(message)s'''
    ),
    datefmt = '%Y-%m-%d ^ %H:%M:%S',
    level = logging.WARNING
)
logger = logging.getLogger(__name__)

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

from asyncio import get_event_loop
from typing import Coroutine

from . import api
from . import defaults
from . import crypto
from . import errors
from . import keys
from . import tools


def sync(coroutine: Coroutine):
    """
    Will call asynchronous function in
    current asyncio loop and return result.
    """
    loop = get_event_loop()
    return loop.run_until_complete(coroutine)

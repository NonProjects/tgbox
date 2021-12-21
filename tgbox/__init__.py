from asyncio import (
    new_event_loop, set_event_loop
)
from typing import Coroutine


__all__ = [
    'api',
    'constants',
    'crypto',
    'db',
    'errors',
    'keys',
    'tools',
    'loop'
]
# Define and set global event loop
loop = new_event_loop()
set_event_loop(loop)


def sync(coroutine: Coroutine):
    """
    Will call asynchronous function
    in ``tgbox.loop`` and return result.
    """
    return loop.run_until_complete(coroutine)

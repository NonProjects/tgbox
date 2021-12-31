from asyncio import (
    new_event_loop, 
    set_event_loop
)
from typing import Coroutine

try:
    # We can use uvloop as event loop
    # on Linux systems, it's around 2x
    # faster than Python's
    import uvloop; FAST_EVENT_LOOP = True
    new_event_loop = uvloop.new_event_loop
except RuntimeError:
    FAST_EVENT_LOOP = False    

__all__ = [
    'api',
    'constants',
    'crypto',
    'db',
    'errors',
    'keys',
    'tools',
    'loop',
    'FAST_EVENT_LOOP'
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

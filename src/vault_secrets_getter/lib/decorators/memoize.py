# pylint: disable=protected-access
"""
Decorator for memoization.

Works on instance methods, not functions.
Requires args and kwargs to be hashable.

"""
from typing import Callable, Any
import wrapt

if __debug__:
    import logging
    logger = logging.getLogger(__name__)


@wrapt.decorator
def memoize(wrapped: Callable, instance: Any,
            args: Any, kwargs: Any) -> Any:
    """Find cached value if it exists, else call method.

    If cache doesn't exist, create a dedicated dictionnary.
    To make the stored values retrievable, we store the method, it's args
    and it's kwargs. This tuple is used as a key, and is the reason why
    args and kwargs must be hashable.

    Args:
        wrapped (Callable): the wrapped method
        instance (Any): the instance in which is defined the wrapped method
        args (Any): arguments to be used by memoized method
        kwargs (Any): kw-arguments to be used by memoized method.
            This comes in the form of a dictionnary on which keys are
            guaranteed to be strings (they are keywords of methods). Thus
            one can leverage this to build a tuple of the sorted key, value
            couples on the keys. This allows to guarantee that the same
            kwargs on multiple calls are recognized as refering to the same
            cached value, and avoid the issue of unordered data structures.

    Returns:
     Any: the output of the memoized method, be it from the cache or
     by calling the method.

    """
    try:
        cache = instance.__cache
    except AttributeError:
        cache = instance.__cache = {}
    key = (wrapped, args, tuple(sorted(kwargs.items())))
    try:
        res = cache[key]
        if __debug__:
            logger.debug("Accessing cached value of '%s'", wrapped)
    except KeyError:
        res = cache[key] = wrapped(*args, **kwargs)
        if __debug__:
            logger.debug("Storing new value of '%s' in cache", wrapped)
    return res

# pylint: disable=too-few-public-methods,attribute-defined-outside-init
"""
Decorator that allows the use of aliases for the 1st argument in a method call.

Works on instance methods only

"""
from typing import Callable, Any
import wrapt

if __debug__:
    import logging
    logger = logging.getLogger(__name__)


class alias_arg0:
    """Alias first argument of decorated method.

    The alias attribute name is passed as an argument to the decorator itself,
    this attribute it then accessed at runtime.

    """

    def __init__(self, alias_attr: str) -> None:
        """Store aliases as attribute.

        Args:
            alias_attr (dict): attribute name under which the dictionnary of
                aliases is stored in the instance defining the decorated
                method.

        """
        self.alias_attr = alias_attr

    @wrapt.decorator
    def __call__(self, wrapped: Callable, instance: Any,
                 args: Any, kwargs: Any) -> Any:
        """Alias first argument in decorated method.

        Keep relevant metadata of aliased method.
        If aliases is None do not change anything, if first arg in alias, then
        replace it with alias.

        Args:
            wrapped (Callable): the wrapped method
            instance (Any): the instance in which is defined the wrapped method
            args (Any): args passed to the wrapped method
            kwargs (Any): kwargs passed to the wrapped method

        Returns:
            Callable: the decorated method

        """
        self.__aliases = getattr(instance, self.alias_attr)
        if self.__aliases:
            if isinstance(args[0], list):
                if args[0][0] in self.__aliases:
                    if __debug__:
                        logger.debug("Aliased arg '%s' changed into '%s'",
                                     args[0][0], self.__aliases[args[0][0]])
                    return wrapped(self.__aliases[args[0][0]], *args[1:],
                                   **kwargs)
            elif isinstance(args[0], str):
                if args[0] in self.__aliases:
                    if __debug__:
                        logger.debug("Aliased arg '%s' changed into '%s'",
                                     args[0], self.__aliases[args[0]])
                    return wrapped(self.__aliases[args[0]], *args[1:],
                                   **kwargs)
        return wrapped(*args, **kwargs)

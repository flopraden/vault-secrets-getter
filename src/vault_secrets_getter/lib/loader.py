# pylint: disable=unused-argument
"""
Contains the loader classes.

More documentation incoming.
"""
import importlib
import re
from abc import ABC, abstractmethod
from typing import Any, Optional
import types

from .decorators.memoize import memoize
from .decorators.aliases import alias_arg0

if __debug__:
    import logging
    logger = logging.getLogger(__name__)


class LoaderABC(ABC):
    """ABC for loader classes, promise of interface."""

    @abstractmethod
    def get_module(self, module_name: str) -> Any:
        """Return the specified module."""

    @abstractmethod
    def get_class(self, total_class_name: str) -> Any:
        """Return the specified class."""

    @abstractmethod
    def get_instance(self, total_class_name: str, *args: Any, **kwargs: Any
                     ) -> Any:
        """Return the an instance of the specified class.

        Instantiated with args and kwargs
        """


class Loader(LoaderABC):
    """Load modules, classes, instances."""

    def __init__(self, alias: Optional[dict] = None, package: Optional[str] = None) -> None:
        """Store the alias to globally declared attribute name.

        To ensure consistency between different classes, we have a single
        source of truth concerning the attribute name for storing aliases.

        Args:
            alias (dict): dictionnary of aliases that can be used instead of
                full path name.

        """
        setattr(self, "_Loader__alias", alias)
        setattr(self, "_Loader__package", package)

    def __new__(cls, *args, **kwargs) -> Any:
        """Raise error if class is directly instantiated."""
        if cls is Loader:
            raise TypeError("Base class may not be instantiated")
        return super().__new__(cls)

    def get_module(self, module_name: str) -> types.ModuleType:
        """Return the specified module."""
        if __debug__:
            logger.debug("Importing module '%s'", module_name)
        try:
            module = importlib.import_module(module_name, getattr(self, "_Loader__package"))
        except ImportError:
            if __debug__:
                logger.critical("Error importing module '%s'", module_name)
            raise
        return module

    def get_class(self, total_class_name: str) -> Any:
        """Return the specified class."""
        module_name, class_name = total_class_name.rsplit('.', 1)
        if __debug__:
            logger.debug("Loading from module '%s' class '%s'",
                         module_name, class_name)
        module = self.get_module(module_name)
        if hasattr(module, class_name):
            retclass = getattr(module, class_name)
        else:
            if __debug__:
                logger.critical(
                    "Error importing class '%s' from '%s'", class_name,
                    module_name)
            raise ImportError('%s' % (total_class_name))
        return retclass

    @alias_arg0(alias_attr="_Loader__alias")
    def get_instance(self, total_class_name: str, *args: Any, **kwargs: Any
                     ) -> Any:
        """Instanciate class with args and kwargs.

        Args:
            total_class_name (str): total path to the class.
            *args (Any): args to be used to instantiate.
            **kwargs (Any): kwargs to be used to instantiate.

        Returns:
            Any: Instance of requested class.

        """
        if __debug__:
            logger.debug(
                "Return new instance of class '%s',\n"
                "\targs = %s, \n"
                "\tkwargs = %s",
                total_class_name, args, kwargs)
        requested_class = self.get_class(total_class_name)
        instance = requested_class(*args, **kwargs)
        return instance


class LoaderFiltered(Loader):
    """Accept to load only explicitly authorized classes."""

    def __init__(self, alias: Optional[dict] = None,
                 filters: Optional[list] = None, 
                 package: Optional[str] = None) -> None:
        """Store filters in attribute, pass along alias to parent class."""
        super().__init__(alias=alias, package=package)
        self._filters = filters if filters else []
        # super().__init__(alias=alias)

    @memoize
    @alias_arg0(alias_attr="_Loader__alias")
    def get_module(self, module_name: str) -> types.ModuleType:
        """Wrap parent class method and adds a simple filtering operation."""
        if module_name not in self._filters:
            raise ImportError(
                "Module '%s' not in authorized module" % (module_name))

        return Loader.get_module(self, module_name)

    @memoize
    @alias_arg0(alias_attr="_Loader__alias")
    def get_class(self, total_class_name: str) -> Any:
        """Wrap parent class method and adds a simple filtering operation."""
        if total_class_name not in self._filters:
            raise ImportError(
                "Class '%s' not in authorized class" % (total_class_name))
        return Loader.get_class(self, total_class_name)


class LoaderREFiltered(Loader):
    """Accept to load classes that match one of a list of regexp."""

    def __init__(self, alias: Optional[dict] = None,
                 filters: Optional[list] = None, 
                 package: Optional[str] = None) -> None:
        """Store filters in attribute, pass along alias to parent class.

        Transform raw strings to compiled regexp and store it in list.
        """
        super().__init__(alias=alias, package=package)
        self._filters: list = []
        filters = filters if filters else []
        for filt in filters:
            self._filters.append(re.compile(filt))

    @memoize
    @alias_arg0(alias_attr="_Loader__alias")
    def get_module(self, module_name: str) -> types.ModuleType:
        """Wrap parent class method and adds a regexp filtering operation."""
        for filt in self._filters:
            if filt.match(module_name):
                return Loader.get_module(self, module_name)
        raise ImportError(
            "Module '%s' not in authorized module" % (module_name))

    @memoize
    @alias_arg0(alias_attr="_Loader__alias")
    def get_class(self, total_class_name: str) -> Any:
        """Wrap parent class method and adds a regexp filtering operation."""
        for filt in self._filters:
            if filt.match(total_class_name):
                return Loader.get_class(self, total_class_name)
        raise ImportError(
            "Class '%s' not in authorized class" % (total_class_name))


import structlog

import logging
logger = logging.getLogger(__name__)

from ..lib.loader import LoaderFiltered
from ..SecretInstaller.base import MissingSecretInstaller


class SecretGetter:
    def __init__(self, *args, **kwargs):
        super().__init__()
        self._conf(args, kwargs)

    def _conf(self, args, kwargs):
        self._config = kwargs.get("config")

    def _get(self, path: str, dir: str ="/", pmeta:dict|None = None):
        # Should return {secret: Dict, metadata: Dict}
        raise NotImplementedError()
    
    def _gets(self, path: str, dir: str="/", pmeta:dict|None = None):
        # Should return list of (sub, subpath)
        raise NotImplementedError()
    
    def get(self, path: str, dir: str="/", pmeta:dict|None = None):
        # Should return {path: {secret: Dict, metadata: Dict}}
        raise NotImplementedError()
    

class Secret(SecretGetter):
    # Get Secret Installer for each path and following aliases
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._loader = LoaderFiltered(
            alias = self._config["INSTALLER_ALIAS"],
            filters = self._config["INSTALLER_FILTER"], 
            package = "vault_secrets_getter")
    
    def _get(self, path: str, dir:str="/", pmeta:dict|None = None):
        ret = super()._get(path, dir, pmeta)
        if len(ret) == 0:
            return {}
        mtype = None
        stype = None
        type = None
        meta = ret["secret"]["metadata"]["custom_metadata"]
        try:
            if meta is not None:
                mtype = meta["secretType"]
        except KeyError:
            # No secret type or no custom metadata
            pass
        try:
            stype = ret["secret"]["data"]["secretType"]
        except KeyError:
            # No secret type or no custom metadata
            pass
        type = mtype or stype
        if type is not None:
            match type:
                case "alias":
                    # Maybe should be dealt as AliasSecret & Secrets for type
                    try:
                        npath = ret["secret"]["data"]["link"]
                        ret = self.get(npath, dir=dir, pmeta=(meta or pmeta))
                        if len(ret) == 0:
                            logger.info(f"{path}>>{npath} : No secret found")
                            return {}
                        return ret
                    except KeyError as e:
                        logger.error(f"No link in secret {path} with type {type}")
                        return {}
                case _:
                    try:
                        return {path: self._loader.get_instance(type, dir=dir, path=path, config=self._config, secret=ret, getter=self, parentmeta=pmeta)}
                    except ImportError as e:
                        logger.error(f"Cannot install returned secret of type {type} : {e!s}")
                        raise MissingSecretInstaller(type=type, secret=ret)
        else:
            # Use default SecretInstaller
            try:
                return {path: self._loader.get_instance("default", dir=dir, path=path, config=self._config, secret=ret, getter=self)}
            except ImportError as e:
                logger.error(f"Cannot install returned secret of type {type} : {e!s}")
                raise MissingSecretInstaller(type="default", secret=ret)


    def get(self, path:str, dir: str = "/", pmeta:dict|None = None):
        # Recursively return dict of SecretInstaller
        # List all subpath and current path to search secret to install

        # Try to read current path as a secret
        ret = {}
        try:
            ret = self._get(path, dir, pmeta)
        except MissingSecretInstaller:
            logger.info(f"No installable secret in {path}")

        # Try to read current path as a dir of secret
        for (sub, subpath) in self._gets(path, dir, pmeta):
                ret.update(self.get(subpath, dir + sub, pmeta=pmeta))
        
        # Did we have some secrets ?
        if len(ret) == 0:
            logger.info(f"No secrets in ${path}")

        # return all secret received
        return ret

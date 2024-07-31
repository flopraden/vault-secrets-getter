import structlog
import os 
import posix1e
import shutil
import json
import copy

import base64 as b64

import logging
logger = logging.getLogger(__name__)

"""
{"user": "user", "group": "group", "perms": "0o777", "extended": "", "extraPerms": { "/A/B": { "user": "A", "group" : "gA", "perms": "0o744", "extended" : "user:adminqs:r--,user:root:rwx,mask::rwx"}, "/A": { "user": "A", "group" : "gA", "perms": "0o755", "extended" : "user:root:rwx,mask::rwx"} }}
"""
class MissingSecretInstaller(Exception):
    def __init__(self, type, secret, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._type = type
        self._secret = secret
    def __str__(self):
        return f"Can't install secret of type {self._type}"

    def __repr__(self):
        return f'InstallSecretError({type}, XXXXXX)'

class SecretInstaller:
    ERR_STR = {
        posix1e.ACL_MULTI_ERROR: "The ACL contains multiple entries that have a tag type that may occur at most once.",
        posix1e.ACL_DUPLICATE_ERROR: "The ACL contains multiple ACL_USER or ACL_GROUP entries with the same ID.",
        posix1e.ACL_MISS_ERROR: "A required entry is missing.",
        posix1e.ACL_ENTRY_ERROR: "The ACL contains an invalid entry tag type."
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__()
        self._secretFiles = {}
        self._meta = {}
        self._parentmeta = {}
        self._dirname = None
        self._filename = None
        self._parentPerms = {}
        self._curPerms = {}
        self._conf(args, kwargs)
        

    @staticmethod
    def sanitize_path(path: str) -> str:
        if path == "":
            return "/"
        if path[0] != '/':
            path = "/" + path
        if path[-1] == '/':
            path = path[:-1]
        return path
    
    @staticmethod
    def _changePerm(file: str, perm: str|None = None, extended: str|None = None) -> bool:
        ret = True
        if perm is not None:
            ret &= SecretInstaller._changeSPerm(file, perm)
        if extended is not None:
            ret &= SecretInstaller._changeExtendedPerm(file, extended)
        return ret
    
    @staticmethod
    def _changeSPerm(file: str, perm: str|None = None) -> bool:
        if perm is None:
            return False
        try:
            iPerm = int(perm, base=8)
        except ValueError as e:
            logger.error(f"Can't convert {perm} to integer value. perm should be 0oXXX in octal mode: {e!s}")
            return False
        try:
            os.chmod(file, iPerm)
        except Exception as e:
            logger.error(f"Can't change perm on file {file}: {e!s}")
            return False
        return True
    
    @staticmethod
    def _changeExtendedPerm(file: str, extended: str|None = None) -> bool:
        if extended is None:
            return False
        try:
            acl = posix1e.ACL(text=extended)
        except OSError as e:
            logger.error(f"'{extended}' is not correct extended permission: {e!s}")
            return False
        try:
            if not acl.valid():
                logger.error(f"Extended permission '{extended}' not valid:")
                err = acl.check()
                sErr = SecretInstaller.ERR_STR.get(err[0], "Unknown error, should not appear")
                logger.error(f"Pos {err[1]}: {sErr}")
                return False
            acl.applyto(file)
        except OSError as e:
            logger.error(f"Can't apply ACL({extended}) to file '{file}")
            return False
        return True
    
    @staticmethod
    def _chown(file: str, user: str|None = None, group: str|None = None) -> bool:
        if user is None and group is None:
            return False
        try:
            shutil.chown(file, user=user, group=group)
        except Exception as e:
            logger.error(f"Can't set permission to file {file} : {e!s}")
            return False
        return True

        
    
    @staticmethod
    def _saveSecret(path: str, content: bytes) -> None:
        with open(path, 'wb') as file:
            file.write(content)
    
    def _conf(self, args, kwargs):
        self._secret = kwargs.get('secret')
        self._getter = kwargs.get('getter')
        self._config = kwargs.get('config')

        self._parentmeta = copy.deepcopy(kwargs.get('parentmeta') or {})
        try:
            self._meta = copy.deepcopy(self._secret["secret"]["metadata"]["custom_metadata"] or {})
        except KeyError:
            # No custom metadata defined
            pass
        self._dir = kwargs.get('dir')
        self._path = kwargs.get('path')
        self._base = self._config["SECRET_BASE_DIR"]

        if self._base is None:
            self._base="/run/secrets"
        
        self._dir = self.sanitize_path(self._dir)
        self._base = self.sanitize_path(self._base)

        self._parentPerms = self._parseJson(self._path, "parentMeta", self._parentmeta.get("secretPerms"), {})
        self._curPerms = self._parseJson(self._path,"meta", self._meta.get("secretPerms"), {})

    @staticmethod
    def _parseJson(path: str, key: str, strJson: str|None, defaultVal: dict|None = None):
        if strJson is None:
            return defaultVal
        # Try to decode JSON
        try:
            return json.loads(strJson)
        except json.JSONDecodeError as e:
            logger.error(f"Can't decode json from secretPerms in {path} § {key} : {e!s}")
            return defaultVal

    def _extractdir(self):
        meta_dirname = self._meta.get("secretDirname") or self._parentmeta.get("secretDirname")
        if meta_dirname is not None and meta_dirname != "":
            self._dir = meta_dirname

        dir = self._base + self._dir

        if self._meta is not None:
            self._filename = self._meta.get("secretFilename") or self._parentmeta.get("secretFilename")
        if self._filename is None:
            self._dirname = os.path.dirname(dir)
            self._filename = os.path.basename(dir)
        else:
            self._dirname = dir

    def _extractExtraPerms(self, meta: dict|None) -> None:
        perms = meta.get("extraPerms")
        if perms is None:
            return
        
        for path, conf in perms.items():
            self._secretFiles[f"{self._base}{path}"] = (
                conf.get("user"),
                conf.get("group"),
                conf.get("perms"),
                conf.get("extended")
            )

    def _get_meta_filepath(self):
        return f"{self._dirname}/{self._filename}.meta"
    
    def _checkVersion(self) -> bool:
        content = None
        try:
            filepath = self._get_meta_filepath()
            with open(filepath, "r") as f:
                content=json.load(f)
            cur = self._secret["secret"]["metadata"]
            if cur["version"] <= content["version"]:
                return False
        except Exception as e:
            pass
        return True
    
    def _saveVersion(self) -> None:
        cur = self._secret["secret"]["metadata"]
        content = {"created_time": cur["created_time"], "version": cur["version"]}
        try:
            filepath = self._get_meta_filepath()
            with open(filepath, "w") as f:
                json.dump(content, f)
        except Exception as e:
            pass
    
    def _install(self):
        raise NotImplementedError()
    
    def install(self) -> bool:
        # Return if secret as changed (new version installed)
        self._extractdir()
        if not self._checkVersion():
            return False
        self.makedir()
        # try to see if we have perm/owner change saved in metadata
        # Try in parent meta and meta
        self._extractExtraPerms(self._parentPerms)
        self._extractExtraPerms(self._curPerms)

        self._install()
        # Extract owner & perms
        for path, (user, group, perms, extended) in self._secretFiles.items():
            self._chown(path, user=user, group=group)
            self._changePerm(path, perms, extended)
        self._saveVersion()
        return True

    def _install(self, path: str = ""):
        raise NotImplementedError()
    
    def makedir(self):
        if self._dirname is None:
            return
        os.makedirs(self._dirname, exist_ok=True)
        
class log(SecretInstaller):
    def install(self):
        logger.info(f"path : {self._path}")
        logger.info(f"secret : {self._secret}")
        logger.info(f"dir : {self._dirname}")
        logger.info(f"file : {self._filename}")
    

class baseX(SecretInstaller):
    DECODER=staticmethod(b64.b64decode)
    def _get_meta_filepath(self):
        return f"{self._base}{self._dir}/.meta"
    
    def _install(self):
        perm = copy.deepcopy(self._parentPerms)
        perm.update(self._curPerms)
        dir = self._base + self._dir
        binary = (self._meta.get("secretBinary", "0") == "1")
        try:
            for secretName,content in self._secret["secret"]["data"].items():
                filepath = f"{dir}/{secretName}"
                try:
                    decoded = self.DECODER(content)
                except Exception as e:
                    logger.error(f"Can't decode secret in path {self._path} named {secretName} : {e!s}")
                    continue
                try:
                    if binary:
                        with open(filepath, 'wb') as file:
                            file.write(decoded)
                    else:
                        with open(filepath, 'wt') as file:
                            file.write(decoded.decode("utf_8"))
                except OSError as e:
                    logger.error(f"Can't save secret in {dir} with name {secretName} : {e!s}")
                    continue
                self._secretFiles[filepath] = (
                    perm.get("user"),
                    perm.get("group"),
                    perm.get("perms"),
                    perm.get("extended")
                )
        except KeyError as e:
            logger.error(f"Can't get secret in {dir}")
        
class base16(baseX):
    DECODER=staticmethod(b64.b16decode)

class base32(baseX):
    DECODER=staticmethod(b64.b32decode)

class base64(baseX):
    DECODER=staticmethod(b64.b64decode)

class basea85(baseX):
    DECODER=staticmethod(b64.a85decode)


class envfile(SecretInstaller):
    def _extractdir(self):
        super()._extractdir()
        # For now, last part of the name of the secret is not passed.
        # TODO: change all that
        self._dirname = f"{self._dirname}/{self._filename}"
        self._filename = os.path.basename(self._path)

    def _install(self):
        filepath = f"{self._dirname}/{self._filename}"
        try:
            with open(filepath, 'wt') as file:
                for k,v in self._secret["secret"]["data"].items():
                    try:
                        file.write(f"{k}={v}\n")
                    except OSError as e:
                        logger.error(f"Error when writing secret in file: {filepath}: {k} => {v} : {e!s}")
        except KeyError as e:
            logger.error(f"Can't get secret in {self._path} : {e!s}")
        except OSError as e:
            logger.error(f"Error when opening the file {filepath} : {e!s}")
        
        # Get permission from parent & current secret
        perm = copy.deepcopy(self._parentPerms)
        perm.update(self._curPerms)
        self._secretFiles[filepath] = (
                perm.get("user"),
                perm.get("group"),
                perm.get("perms"),
                perm.get("extended")
        )
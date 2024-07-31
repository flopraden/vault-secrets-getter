import structlog
import os
import copy

from .base import SecretInstaller

import logging
logger = logging.getLogger(__name__)


class x509(SecretInstaller):
    FILENAME = {
        "cert": "cert.crt",
        "chain": "chain.pem",
        "fullchain": "fullchain.pem",
        "key": "cert.key"
    }
#    def __init__(self, *args, **kwargs):
#        super().__init__(*args, **kwargs)

    def _get_meta_filepath(self):
        return f"{self._base}{self._dir}/.meta"
    
    def _install(self):
        """
        {
           "cert": "<ASCII DATA>",
            "chain": "<ASCII DATA>",
            "domains": [
                "domain1"
                "domain2"
            ],
            "fullchain": "<ASCII DATA>",
            "key": "<ASCII DATA>",
            "life": {
                "expires": timestamp,
                "issued": timestamp
            },
            "serial": "<CERT SERIAL",
            "type": "urn:scheme:type:certificate"
        }
        """
        perm = copy.deepcopy(self._parentPerms)
        perm.update(self._curPerms)
        dir = self._base + self._dir
        for filekey,filename in x509.FILENAME.items():
            # Get permission from parent & current secret
            try:
                content = self._secret["secret"]["data"][filekey]
                filepath=f"{dir}/{filename}"
                with open(filepath, 'wt') as file:
                    file.write(content)
                self._secretFiles[filepath] = (
                    perm.get("user"),
                    perm.get("group"),
                    perm.get("perms"),
                    perm.get("extended")
                )
            except KeyError as e:
                logger.error(f"Can't get x509 data of {filekey} in {self._path} : {e!s}")
            except OSError as e:
                logger.error(f"Error when opening/writing the file {filepath} : {e!s}")

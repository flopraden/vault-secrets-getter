import hvac
import structlog
import requests

import pprint

from .Secrets import SecretGetter

import logging
logger = logging.getLogger(__name__)

def get_vault_client(vault_url, certs):
        """
        Instantiates a hvac / vault client.
        :param vault_url: string, protocol + address + port for the vault service
        :param certs: tuple, Optional tuple of self-signed certs to use for verification
                with hvac's requests adapter.
        :return: hvac.Client
        """
        logger.debug('Retrieving a vault (hvac) client...')
        vault_client = hvac.Client(
                url=vault_url,
                verify=certs,
        )
        if certs:
        # When use a self-signed certificate for the vault service itself, we need to
        # include our local ca bundle here for the underlying requests module.
                rs = requests.Session()
                vault_client.session = rs
                rs.verify = certs

        return vault_client

class VaultClient(SecretGetter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _conf(self, args, kwargs):
        super()._conf(args, kwargs)
        self._config = kwargs.get("config")
        self._hvac_client = get_vault_client(
             self._config["VAULT_ADDRESS"], 
             self._config["VAULT_CA"]
        )
        self._auth()

    def _auth(self):
        if self._config["VAULT_TOKEN"]:
            self._hvac_client.token = self._config["VAULT_TOKEN"]

        if self._config["VAULT_ROLE_ID"] and self._config["VAULT_SECRET_ID"]:
            auth_mount_point = self._config["VAULT_AUTHPATH"] or 'approle'
            self.hvac_client.auth.approle.login(
                self._config["VAULT_ROLE_ID"],
                self._config["VAULT_SECRET_ID"],
                mount_point=auth_mount_point
            )

        if self._config["VAULT_JWT_ROLE"] and self._config["VAULT_JWT_KEY"]:
            self._hvac_client.auth.jwt.jwt_login(
                self._config["VAULT_JWT_ROLE"],
                self._config["VAULT_JWT_KEY"],
                path=self._config["VAULT_AUTHPATH"]
            )
    def _get(self, path: str, dir: str ="/", pmeta:dict|None = None):
        if not self._hvac_client.is_authenticated():
            raise Exception('Not authenticated')
        mount_point = self._config["VAULT_SECRETS_MOUNTPOINT"] or "kv"
        try:
            resp = self._hvac_client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount_point
            )
            mresp = self._hvac_client.secrets.kv.v2.read_secret_metadata(
                path = path,
                mount_point=mount_point
            )
        except hvac.exceptions.InvalidPath as e:
            logger.debug(f"{path} has no secret")
            return {}
        try:
            return {
                "secret": resp["data"],
                "metadata": mresp["data"]
            }
        except KeyError as e:
            logger.debug(f"_get return keyerror: {e!s}")
            return {}
    
    def _gets(self, path: str, dir: str ="/", pmeta:dict|None = None):
        if not self._hvac_client.is_authenticated():
            raise Exception('Not authenticated')
        mount_point = self._config["VAULT_SECRETS_MOUNTPOINT"] or "kv"
        if path[-1] == '/':
             path = path[:-1]
        try:
            resp = self._hvac_client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=mount_point
            )
        except hvac.exceptions.InvalidPath as e:
            logger.debug(f"{path} is not a directory")
            return []
        try:
            return [ (k, f"{path}/{k}") for k in resp["data"]["keys"]]
        except KeyError as e:
            logger.debug(f"gets return keyerror: {e!s}")
            return []
    

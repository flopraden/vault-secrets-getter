from typing import Optional
from ..lib.config import Config as BaseConfig


class Config(BaseConfig):
    """Basic configuration class."""
    VAULT_ADDRESS: str = "http://127.0.0.1"
    VAULT_CA: Optional[str] = None
    VAULT_TOKEN: Optional[str] = None
    VAULT_ROLE_ID: Optional[str] = None
    VAULT_ROLE_SECRET: Optional[str] = None
    VAULT_JWT_ROLE: Optional[str] = None
    VAULT_JWT_KEY: Optional[str] = None
    VAULT_AUTHPATH: Optional[str] = None
    VAULT_SECRETS_MOUNTPOINT: Optional[str] = None
    SECRET_BASE_DIR: Optional[str] = None
    INSTALLER_ALIAS: dict = {
        "default": ".SecretInstaller.base.log",
        "x509": ".SecretInstaller.Certs.x509",
        "base64": ".SecretInstaller.base.base64",
        "envfile": ".SecretInstaller.base.envfile",
    }
    INSTALLER_FILTER: list = [
        ".SecretInstaller",
        ".SecretInstaller.Certs",
        ".SecretInstaller.Certs.x509",
        ".SecretInstaller.base",
        ".SecretInstaller.base.base16",
        ".SecretInstaller.base.base32",
        ".SecretInstaller.base.base64",
        ".SecretInstaller.base.base85",
        ".SecretInstaller.base.envfile",
        ".SecretInstaller.base.log"
    ]


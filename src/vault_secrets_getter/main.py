import argparse
import logging
import logging.config

import os
import sys

from .conf.config import Config

from .SecretClient.Vault import VaultClient
from .SecretClient.Secrets import Secret

class VaultSecret(Secret, VaultClient):
    pass

logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    
    parser.add_argument('--loggerconf', type=str, default="logger.conf",
                    help='path config for logger')
    
    parser.add_argument('--config', type=str, default="VAULTSECRETSGETTER_CONFFILE",
                    help='Config param (depend on config type)')
    parser.add_argument('--config-type', default="ENVVAR",
                         type=str, choices=['JSON', 'FILE', 'OBJECT', 'ENVVAR'], 
                         help='Type of config')

    parser.add_argument('--secret-path', type=str, required=True, help='Path of the secret')
    parser.add_argument('--localdir-secret', type=str, required=True, help='local directory to put secrets')

    args = parser.parse_args()

    climain(args)

def climain(args):
    if os.path.isfile(args.loggerconf):
        logging.config.fileConfig(args.loggerconf, disable_existing_loggers=False)
    else:
        # stdout handler
        stdhandler = logging.StreamHandler()
        log_formatter = logging.Formatter()
        stdhandler.setLevel(logging.INFO)
        stdhandler.setFormatter(log_formatter)
        logger.addHandler(stdhandler)

        # change logger level here
        logger.setLevel(logging.INFO)
    
    cfg = Config(os.environ['PWD'])
    conf_loader = getattr(cfg, f"from_{args.config_type.lower()}")
    conf_loader(args.config)

    if args.localdir_secret is not None:
        cfg["SECRET_BASE_DIR"] = args.localdir_secret

    secret=VaultSecret(config=cfg)
    ret = secret.get(args.secret_path)
    changed = False
    for p,v in ret.items():
        changed |= v.install()

    if changed:
        sys.exit(1)
    sys.exit(0)
    

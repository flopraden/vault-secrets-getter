from setuptools import setup, find_packages

setup(
    name='vault-secrets-getter',
    py_modules=['vault-secrets-getter'],
    packages=find_packages(
        # All keyword arguments below are optional:
        where='src',  # '.' by default
#        include=['mypackage*'],  # ['*'] by default
#        exclude=['mypackage.tests'],  # empty by default
    ),
    package_dir={"": "src"}, 
    entry_points={
        'console_scripts': [
            'vault-secrets-getter = vault_secrets_getter:main',
        ],
    }
)

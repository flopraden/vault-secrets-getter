{ pkgs ? import <nixpkgs> { } }:
pkgs.python3Packages.callPackage (
{ lib
, buildPythonPackage
, fetchFromGitHub
, pytestCheckHook
, pythonOlder
, pylibacl
, hvac
, wrapt
, structlog
, requests
}:

buildPythonPackage rec {
    pname = "vault-secrets-getter";
    version = "1.0";
    src = lib.cleanSource ./.;

    disabled = pythonOlder "3.8";

    format = "setuptools";

  propagatedBuildInputs = [
    pylibacl
    hvac
    wrapt
    structlog
  ];
  nativeCheckInputs = [
    pytestCheckHook
  ];
  doCheck = false;
  meta = with lib; {
    description = "Secret getter from vault";
    homepage = "https://github.com/flopraden/vault-secrets-getter";
    changelog = "https://github.com/flopraden/vault-secrets-getter/README.md";
    license = licenses.gpl3Plus;
    maintainers = with maintainers; [ ];
  };
}) { }

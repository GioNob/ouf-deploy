"""Detached Ed25519 signature over the owner's immutable READY receipt."""
from pathlib import Path
import subprocess

from module_release.contract import require
from store import bound, save_bytes, trusted


OPENSSL = "/usr/bin/openssl"
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")


def public_key(binding):
    require(binding, "MODULE_RECEIPT_SIGNER_REQUIRED")
    public = bound(binding["publicKey"])
    der = public.read_bytes()
    require(len(der) == len(ED25519_SPKI) + 32 and der.startswith(ED25519_SPKI), "MODULE_RECEIPT_PUBLIC_KEY")
    return public


def signing_key(binding):
    public = public_key(binding)
    private = trusted(binding["privateKey"], private=True)
    res = subprocess.run([str(trusted(Path(OPENSSL))), "pkey", "-in", str(private), "-pubout", "-outform", "DER"],
                         stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=10)
    require(res.returncode == 0 and res.stdout == public.read_bytes(), "MODULE_RECEIPT_KEY_MISMATCH")
    return private


def attest(binding, directory, *, issue=False):
    public = public_key(binding)
    receipt = trusted(directory / "receipt.json", private=True)
    sigfile = directory / "receipt.ed25519"
    command = [str(trusted(Path(OPENSSL))), "pkeyutl", "-rawin", "-in", str(receipt)]
    options = dict(stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    if issue and not sigfile.exists():
        private = signing_key(binding)
        res = subprocess.run([*command, "-sign", "-inkey", str(private)], stdout=subprocess.PIPE, **options)
        require(res.returncode == 0 and len(res.stdout) == 64, "MODULE_RECEIPT_SIGN_FAILED")
        save_bytes(sigfile, res.stdout)
    require(sigfile.is_file() and trusted(sigfile, private=True).stat().st_size == 64, "MODULE_RECEIPT_SIGNATURE_REQUIRED")
    res = subprocess.run([*command, "-verify", "-pubin", "-keyform", "DER", "-inkey", str(public),
                          "-sigfile", str(sigfile)], stdout=subprocess.DEVNULL, **options)
    require(res.returncode == 0, "MODULE_RECEIPT_SIGNATURE_INVALID")

"""VaultPack Python bindings.

This package provides a thin Python wrapper around `libvaultpack`, the
VaultPack C-shared library. It uses :mod:`ctypes` (no compiler required at
install time) and works on Linux, macOS, and Windows.

Quick start::

    import vaultpack

    res = vaultpack.protect(
        input_path="secret.txt",
        output_path="secret.vpack",
    )
    key = res["generated_key_b64"]  # save this somewhere safe!

    out = vaultpack.decrypt(
        input_path="secret.vpack",
        key_b64=key,
    )
    print(out["plaintext_b64"])

See ``README.md`` for the full API.
"""

from .core import (
    VERSION,
    VaultpackError,
    decrypt,
    inspect,
    protect,
    sign,
    verify,
    version,
)

__all__ = [
    "VERSION",
    "VaultpackError",
    "decrypt",
    "inspect",
    "protect",
    "sign",
    "verify",
    "version",
]

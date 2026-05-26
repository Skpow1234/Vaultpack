"""Low-level ctypes wrapper around libvaultpack.

The library is located via the following resolution order:

1. ``$VAULTPACK_LIB`` environment variable (absolute path).
2. A copy adjacent to this module (``vaultpack/libvaultpack.{so,dylib,dll}``).
3. ``ctypes.util.find_library('vaultpack')`` (system loader).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import platform
import sys
from typing import Any, Optional

VERSION = "0.1.0"  # bumped together with the Go SDK.


class VaultpackError(RuntimeError):
    """Raised when an SDK call returns ``{"ok": false}`` or fails to load."""


def _libname() -> str:
    system = platform.system()
    if system == "Linux":
        return "libvaultpack.so"
    if system == "Darwin":
        return "libvaultpack.dylib"
    if system == "Windows":
        return "libvaultpack.dll"
    raise VaultpackError(f"unsupported platform: {system}")


def _candidate_paths() -> list[str]:
    paths: list[str] = []
    env = os.environ.get("VAULTPACK_LIB")
    if env:
        paths.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    paths.append(os.path.join(here, _libname()))
    found = ctypes.util.find_library("vaultpack")
    if found:
        paths.append(found)
    return paths


def _load_library() -> ctypes.CDLL:
    last_err: Optional[Exception] = None
    for path in _candidate_paths():
        if not path:
            continue
        try:
            return ctypes.CDLL(path)
        except OSError as exc:
            last_err = exc
    raise VaultpackError(
        "libvaultpack not found. Set VAULTPACK_LIB=/path/to/libvaultpack."
        f"{_ext_for_msg()} or place the library next to vaultpack/core.py. "
        f"Last loader error: {last_err}"
    )


def _ext_for_msg() -> str:
    return {"Linux": "so", "Darwin": "dylib", "Windows": "dll"}.get(
        platform.system(), "so"
    )


_LIB = _load_library()

# Bind the C signatures.
_LIB.vp_version.argtypes = []
_LIB.vp_version.restype = ctypes.c_char_p
_LIB.vp_free.argtypes = [ctypes.c_void_p]
_LIB.vp_free.restype = None

# For functions that return malloc'd strings we use c_void_p so we can
# explicitly free() the pointer after copying the bytes out — using
# c_char_p would let ctypes free it (or not) on its own, which is unsafe
# across the Go/C boundary.
for sym in ("vp_protect", "vp_decrypt", "vp_inspect", "vp_sign", "vp_verify"):
    fn = getattr(_LIB, sym)
    fn.argtypes = [ctypes.c_char_p]
    fn.restype = ctypes.c_void_p


def _call_json(symbol: str, payload: Any) -> dict:
    """Marshal *payload* (str or dict) to JSON, call the C entry point, then
    parse the JSON reply. Always frees the returned C string."""
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
    else:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    fn = getattr(_LIB, symbol)
    ptr = fn(encoded)
    if not ptr:
        raise VaultpackError(f"{symbol}: null reply from libvaultpack")

    try:
        raw = ctypes.string_at(ptr).decode("utf-8")
    finally:
        _LIB.vp_free(ptr)

    try:
        reply = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VaultpackError(f"{symbol}: invalid JSON reply: {exc}: {raw!r}")

    if not isinstance(reply, dict) or not reply.get("ok", False):
        msg = reply.get("error", "unknown error") if isinstance(reply, dict) else raw
        raise VaultpackError(f"{symbol}: {msg}")
    return reply


# --- Public API ----------------------------------------------------------

def version() -> str:
    """Return the libvaultpack semver string (matches ``vaultpack.Version``)."""
    raw = _LIB.vp_version()
    if not raw:
        raise VaultpackError("vp_version returned null")
    return raw.decode("utf-8")


def protect(
    *,
    input_path: Optional[str] = None,
    plaintext: Optional[bytes] = None,
    output_path: str,
    key: Optional[bytes] = None,
    password: Optional[str] = None,
    cipher: Optional[str] = None,
    aad: Optional[bytes] = None,
    input_name: Optional[str] = None,
) -> dict:
    """Encrypt a file or in-memory blob into a .vpack bundle.

    Either ``input_path`` or ``plaintext`` must be supplied, but not both.
    If neither ``key`` nor ``password`` is supplied a fresh 256-bit key is
    generated and returned in the result as ``generated_key_b64`` (base64).
    """
    import base64

    if (input_path is None) == (plaintext is None):
        raise VaultpackError("protect: exactly one of input_path or plaintext is required")

    payload: dict[str, Any] = {"output_path": output_path}
    if input_path is not None:
        payload["input_path"] = input_path
    if plaintext is not None:
        payload["plaintext_b64"] = base64.b64encode(plaintext).decode("ascii")
    if key is not None:
        payload["key_b64"] = base64.b64encode(key).decode("ascii")
    if password is not None:
        payload["password"] = password
    if cipher is not None:
        payload["cipher"] = cipher
    if aad is not None:
        payload["aad_b64"] = base64.b64encode(aad).decode("ascii")
    if input_name is not None:
        payload["input_name"] = input_name
    return _call_json("vp_protect", payload)


def decrypt(
    *,
    input_path: Optional[str] = None,
    bundle: Optional[bytes] = None,
    output_path: Optional[str] = None,
    key: Optional[bytes] = None,
    key_b64: Optional[str] = None,
    password: Optional[str] = None,
    aad: Optional[bytes] = None,
) -> dict:
    """Decrypt a .vpack bundle.

    Either ``input_path`` or ``bundle`` (raw bytes) must be supplied.
    Either ``key``/``key_b64`` or ``password`` must be supplied.
    If ``output_path`` is omitted, the plaintext is returned base64-encoded
    as ``plaintext_b64`` in the result dict.
    """
    import base64

    if (input_path is None) == (bundle is None):
        raise VaultpackError("decrypt: exactly one of input_path or bundle is required")
    if (key is None and key_b64 is None) and password is None:
        raise VaultpackError("decrypt: key or password is required")

    payload: dict[str, Any] = {}
    if input_path is not None:
        payload["input_path"] = input_path
    if bundle is not None:
        payload["bundle_b64"] = base64.b64encode(bundle).decode("ascii")
    if output_path is not None:
        payload["output_path"] = output_path
    if key is not None:
        payload["key_b64"] = base64.b64encode(key).decode("ascii")
    elif key_b64 is not None:
        payload["key_b64"] = key_b64
    if password is not None:
        payload["password"] = password
    if aad is not None:
        payload["aad_b64"] = base64.b64encode(aad).decode("ascii")
    return _call_json("vp_decrypt", payload)


def inspect(path: str) -> dict:
    """Return the parsed manifest of a .vpack bundle without decrypting it."""
    return _call_json("vp_inspect", path)


def sign(
    *,
    bundle_path: str,
    private_key_pem: Optional[str] = None,
    private_key_path: Optional[str] = None,
    algo: Optional[str] = None,
) -> dict:
    """Add (or replace) a detached signature in an existing .vpack file."""
    if (private_key_pem is None) == (private_key_path is None):
        raise VaultpackError(
            "sign: exactly one of private_key_pem or private_key_path is required"
        )
    payload: dict[str, Any] = {"bundle_path": bundle_path}
    if private_key_pem is not None:
        payload["private_key_pem"] = private_key_pem
    if private_key_path is not None:
        payload["private_key_path"] = private_key_path
    if algo is not None:
        payload["algo"] = algo
    return _call_json("vp_sign", payload)


def verify(
    *,
    bundle_path: str,
    public_key_pem: Optional[str] = None,
    public_key_path: Optional[str] = None,
) -> dict:
    """Verify the detached signature of a .vpack file. Returns ``{"valid": bool, ...}``."""
    if (public_key_pem is None) == (public_key_path is None):
        raise VaultpackError(
            "verify: exactly one of public_key_pem or public_key_path is required"
        )
    payload: dict[str, Any] = {"bundle_path": bundle_path}
    if public_key_pem is not None:
        payload["public_key_pem"] = public_key_pem
    if public_key_path is not None:
        payload["public_key_path"] = public_key_path
    return _call_json("vp_verify", payload)


if __name__ == "__main__":  # pragma: no cover - quick smoke test
    print("libvaultpack version:", version(), "(python wrapper", VERSION + ")")
    sys.exit(0)

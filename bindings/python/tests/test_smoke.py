"""End-to-end smoke tests for the vaultpack Python bindings.

Requires libvaultpack to be discoverable (see core._load_library).
"""

import base64
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import vaultpack  # noqa: E402


def test_version() -> None:
    v = vaultpack.version()
    assert isinstance(v, str) and v.count(".") == 2, v


def test_protect_decrypt_roundtrip_keygen() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        in_path = os.path.join(tmp, "secret.txt")
        out_path = os.path.join(tmp, "secret.vpack")
        plain_path = os.path.join(tmp, "secret.out")
        plaintext = b"the quick brown fox jumps over the lazy dog"
        with open(in_path, "wb") as f:
            f.write(plaintext)

        res = vaultpack.protect(input_path=in_path, output_path=out_path)
        assert "generated_key_b64" in res
        assert res["manifest"]["input"]["name"] == "secret.txt"
        assert os.path.exists(out_path)

        key = base64.b64decode(res["generated_key_b64"])
        dec = vaultpack.decrypt(input_path=out_path, output_path=plain_path, key=key)
        assert dec["manifest"]["input"]["name"] == "secret.txt"
        assert open(plain_path, "rb").read() == plaintext


def test_protect_decrypt_password_inmemory() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bundle = os.path.join(tmp, "p.vpack")
        plaintext = b"in-memory roundtrip"
        password = "correct horse battery staple"

        vaultpack.protect(plaintext=plaintext, output_path=bundle, password=password)
        out = vaultpack.decrypt(input_path=bundle, password=password)
        assert base64.b64decode(out["plaintext_b64"]) == plaintext


def test_inspect_returns_manifest() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bundle = os.path.join(tmp, "i.vpack")
        vaultpack.protect(
            plaintext=b"inspectable",
            output_path=bundle,
            cipher="chacha20-poly1305",
        )
        m = vaultpack.inspect(bundle)
        assert m["manifest"]["encryption"]["aead"] == "chacha20-poly1305"


def test_wrong_password_raises() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bundle = os.path.join(tmp, "w.vpack")
        vaultpack.protect(plaintext=b"x", output_path=bundle, password="right")
        try:
            vaultpack.decrypt(input_path=bundle, password="wrong")
        except vaultpack.VaultpackError:
            pass
        else:
            raise AssertionError("expected VaultpackError on wrong password")


if __name__ == "__main__":
    test_version()
    test_protect_decrypt_roundtrip_keygen()
    test_protect_decrypt_password_inmemory()
    test_inspect_returns_manifest()
    test_wrong_password_raises()
    print("all python smoke tests passed")

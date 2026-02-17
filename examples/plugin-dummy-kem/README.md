# Dummy KEM Plugin (Example)

A minimal VaultPack plugin that registers the KEM scheme **`dummy-kem`**. For demonstration only — the "encapsulation" is a trivial XOR and is **not secure**.

## Build

```bash
go build -o dummy-kem .
# On Windows: dummy-kem.exe
```

## Use

1. Put the built executable in a directory and set the plugin dir:

   ```bash
   export VPACK_PLUGIN_DIR=/path/to/dir   # or set plugin_dir in ~/.vpack.yaml
   ```

2. Generate a key pair:

   ```bash
   vaultpack keygen --out demo --algo dummy-kem
   ```

3. Encrypt for the recipient:

   ```bash
   vaultpack protect --in file.txt --recipient demo.pub
   ```

4. Decrypt with the private key:

   ```bash
   vaultpack decrypt --in file.txt.vpack --out file.txt --privkey demo.key
   ```

See the [Plugin Author Guide](../../docs/plugins.md) for the full contract and how to implement your own schemes.

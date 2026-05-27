package keysource

import (
	"os"
	"path/filepath"
	"testing"

	vpcrypto "github.com/Skpow1234/Vaultpack/internal/crypto"
	"github.com/Skpow1234/Vaultpack/internal/util"
)

func testKey() []byte {
	k := make([]byte, vpcrypto.AES256KeySize)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestResolveSymmetricKey_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.key")
	key := testKey()
	if err := vpcrypto.SaveKeyFile(path, key); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSymmetricKey("file://" + path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("key mismatch")
	}
}

func TestResolveSymmetricKey_Env(t *testing.T) {
	key := testKey()
	t.Setenv("VP_TEST_KEY", vpcrypto.KeyFilePrefix+util.B64Encode(key))
	got, err := ResolveSymmetricKey("env://VP_TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("key mismatch")
	}
}

func TestResolveSymmetricKey_B64(t *testing.T) {
	key := testKey()
	got, err := ResolveSymmetricKey("b64://" + util.B64Encode(key))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("key mismatch")
	}
}

func TestResolvePrivateKey_FileEnvB64(t *testing.T) {
	pemBytes := []byte("ed25519-priv:" + util.B64Encode(make([]byte, 64)))
	dir := t.TempDir()
	path := filepath.Join(dir, "sign.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePrivateKey("file://" + path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pemBytes) {
		t.Fatal("file private key mismatch")
	}
	t.Setenv("VP_TEST_PRIV", string(pemBytes))
	got, err = ResolvePrivateKey("env://VP_TEST_PRIV")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pemBytes) {
		t.Fatal("env private key mismatch")
	}
	got, err = ResolvePrivateKey("b64://" + util.B64Encode(pemBytes))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pemBytes) {
		t.Fatal("b64 private key mismatch")
	}
}

func TestUnsupportedSchemes(t *testing.T) {
	for _, uri := range []string{"pkcs11://slot/1", "keychain://vaultpack/sign", "dpapi://vaultpack/key", "piv://slot/9c"} {
		if _, err := ResolveSymmetricKey(uri); err == nil {
			t.Fatalf("expected unsupported error for %s", uri)
		}
	}
}

func TestInvalidSource(t *testing.T) {
	if _, err := ResolveSymmetricKey("not-a-uri"); err == nil {
		t.Fatal("expected syntax error")
	}
	if _, err := ResolveSymmetricKey("env://MISSING_ENV"); err == nil {
		t.Fatal("expected missing env error")
	}
}

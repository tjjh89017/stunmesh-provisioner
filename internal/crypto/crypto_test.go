package crypto_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/tjjh89017/stunmesh-provisioner/internal/crypto"
	"github.com/tjjh89017/stunmesh-provisioner/internal/testvectors"
)

// fixedNonce is the nonce used to produce the golden ciphertext
// vector: the 24 bytes 0x00, 0x01, ... 0x17.
func fixedNonce() [24]byte {
	var nonce [24]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

func goldenCiphertextPath() string {
	return filepath.Join(testvectors.Dir(), "ciphertext.b64")
}

// readGoldenCiphertextBytes reads the committed golden ciphertext vector
// from path. testdata/ciphertext.b64 is a committed vector, not a cache:
// a missing file means the repository is broken, so this reports an
// error instead of silently creating a new (possibly wrong) baseline. To
// deliberately (re)generate the file, run with STUNMESH_REGEN_GOLDEN=1;
// see TestRegenerateGoldenCiphertext and testdata/README.md.
func readGoldenCiphertextBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read golden ciphertext %s: %w (this is a committed test vector; it must exist. Run with STUNMESH_REGEN_GOLDEN=1 to create it deliberately)", path, err)
	}
	return data, nil
}

// readGoldenCiphertext is the test-failing wrapper around
// readGoldenCiphertextBytes.
func readGoldenCiphertext(t testing.TB, path string) []byte {
	t.Helper()

	data, err := readGoldenCiphertextBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// goldenCiphertext returns the sealed (non-base64) bytes of the golden
// ciphertext vector. It recomputes the sealing of
// testvectors.CanonicalJSON() with fixedNonce(), recipient node public
// key, sender controller private key, and asserts the recomputation
// matches the committed testdata/ciphertext.b64 byte-for-byte.
func goldenCiphertext(t *testing.T) []byte {
	t.Helper()

	controllerPriv, _ := testvectors.ControllerKey()
	_, nodePub := testvectors.NodeKey()
	plain := testvectors.CanonicalJSON()

	nonce := fixedNonce()
	recomputed := crypto.SealWithNonce(plain, &nonce, crypto.Key(nodePub), crypto.Key(controllerPriv))
	recomputedB64 := base64.StdEncoding.EncodeToString(recomputed) + "\n"

	path := goldenCiphertextPath()
	existing := readGoldenCiphertext(t, path)

	if string(existing) != recomputedB64 {
		t.Fatalf("%s does not match recomputed golden ciphertext (fixed vector must stay stable)", path)
	}
	return recomputed
}

// TestRegenerateGoldenCiphertext (re)writes testdata/ciphertext.b64 from
// the current Seal implementation. It runs only when STUNMESH_REGEN_GOLDEN
// is "1" (see testdata/README.md); a normal test run never touches the
// file, so a broken Seal cannot self-heal a golden vector into a wrong
// one.
func TestRegenerateGoldenCiphertext(t *testing.T) {
	if os.Getenv("STUNMESH_REGEN_GOLDEN") != "1" {
		t.Skip("set STUNMESH_REGEN_GOLDEN=1 to (re)write testdata/ciphertext.b64")
	}

	controllerPriv, _ := testvectors.ControllerKey()
	_, nodePub := testvectors.NodeKey()
	plain := testvectors.CanonicalJSON()

	nonce := fixedNonce()
	sealed := crypto.SealWithNonce(plain, &nonce, crypto.Key(nodePub), crypto.Key(controllerPriv))
	sealedB64 := base64.StdEncoding.EncodeToString(sealed) + "\n"

	path := goldenCiphertextPath()
	if err := os.WriteFile(path, []byte(sealedB64), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s; review the diff before committing", path)
}

func TestReadGoldenCiphertextBytesFailsOnMissingFileWithoutCreatingIt(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "ciphertext.b64")

	if _, err := readGoldenCiphertextBytes(missing); err == nil {
		t.Fatal("readGoldenCiphertextBytes succeeded on a missing golden file, want an error")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("readGoldenCiphertextBytes created the missing golden file; a committed vector must never self-heal")
	}
}

func TestSealWithNonceReproducesGoldenCiphertext(t *testing.T) {
	// goldenCiphertext fails the test if testdata/ciphertext.b64 is
	// missing, and asserts byte-for-byte equality with a fresh
	// recomputation otherwise.
	goldenCiphertext(t)
}

func TestOpenGoldenCiphertext(t *testing.T) {
	sealed := goldenCiphertext(t)

	_, controllerPub := testvectors.ControllerKey()
	nodePriv, _ := testvectors.NodeKey()

	plain, err := crypto.Open(sealed, crypto.Key(controllerPub), crypto.Key(nodePriv))
	if err != nil {
		t.Fatalf("Open(golden ciphertext) = %v, want success", err)
	}
	if !bytes.Equal(plain, testvectors.CanonicalJSON()) {
		t.Fatalf("Open(golden ciphertext) = %q, want %q", plain, testvectors.CanonicalJSON())
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	recipientPriv, recipientPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(recipient): %v", err)
	}
	senderPriv, senderPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(sender): %v", err)
	}

	plain := []byte("hello stunmesh")

	sealed, err := crypto.Seal(plain, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := crypto.Open(sealed, senderPub, recipientPriv)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("Open round trip = %q, want %q", got, plain)
	}
}

func TestSealTwiceProducesDifferentOutput(t *testing.T) {
	recipientPriv, recipientPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(recipient): %v", err)
	}
	senderPriv, _, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(sender): %v", err)
	}
	_ = recipientPriv

	plain := []byte("same plaintext")

	first, err := crypto.Seal(plain, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal (first): %v", err)
	}
	second, err := crypto.Seal(plain, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal (second): %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatalf("two Seal calls of the same plaintext produced identical output; nonce is not random")
	}
}

func TestOpenFailureCases(t *testing.T) {
	recipientPriv, recipientPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(recipient): %v", err)
	}
	senderPriv, senderPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(sender): %v", err)
	}
	otherPriv, otherPub, err := crypto.Keygen()
	if err != nil {
		t.Fatalf("Keygen(other): %v", err)
	}

	plain := []byte("attack at dawn")
	sealed, err := crypto.Seal(plain, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tests := map[string]struct {
		sealed    []byte
		senderPub crypto.Key
		recipPriv crypto.Key
	}{
		"wrong recipient key": {
			sealed:    sealed,
			senderPub: senderPub,
			recipPriv: otherPriv,
		},
		"wrong sender key": {
			sealed:    sealed,
			senderPub: otherPub,
			recipPriv: recipientPriv,
		},
		"flipped byte": {
			sealed:    flipByte(sealed, len(sealed)-1),
			senderPub: senderPub,
			recipPriv: recipientPriv,
		},
		"truncated below nonce+overhead": {
			// 24-byte nonce + 16-byte Poly1305 tag is the minimum
			// possible length of valid sealed output; one byte
			// short of that can never open successfully.
			sealed:    sealed[:24+box.Overhead-1],
			senderPub: senderPub,
			recipPriv: recipientPriv,
		},
		"empty input": {
			sealed:    nil,
			senderPub: senderPub,
			recipPriv: recipientPriv,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.Open(tc.sealed, tc.senderPub, tc.recipPriv)
			if !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("Open(%s) error = %v, want ErrDecrypt", name, err)
			}
		})
	}
}

func flipByte(in []byte, i int) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	out[i] ^= 0xFF
	return out
}

func TestParseKeyStringRoundTrip(t *testing.T) {
	tests := map[string]func() (priv, pub [32]byte){
		"controller": testvectors.ControllerKey,
		"node":       testvectors.NodeKey,
		"tunnel":     testvectors.TunnelKey,
	}

	for name, loader := range tests {
		t.Run(name, func(t *testing.T) {
			priv, pub := loader()

			privKey, err := crypto.ParseKey(crypto.Key(priv).String())
			if err != nil {
				t.Fatalf("ParseKey(priv.String()): %v", err)
			}
			if privKey != crypto.Key(priv) {
				t.Fatalf("ParseKey(priv.String()) round trip mismatch")
			}

			pubKey, err := crypto.ParseKey(crypto.Key(pub).String())
			if err != nil {
				t.Fatalf("ParseKey(pub.String()): %v", err)
			}
			if pubKey != crypto.Key(pub) {
				t.Fatalf("ParseKey(pub.String()) round trip mismatch")
			}

			if got := crypto.Public(crypto.Key(priv)); got != crypto.Key(pub) {
				t.Fatalf("Public(priv) = %s, want %s", got, crypto.Key(pub))
			}
		})
	}
}

func TestParseKeyRejectsBadInput(t *testing.T) {
	tests := map[string]string{
		"31 bytes":   base64.StdEncoding.EncodeToString(make([]byte, 31)),
		"33 bytes":   base64.StdEncoding.EncodeToString(make([]byte, 33)),
		"bad base64": "not-valid-base64!!!",
	}

	// The empty string decodes as zero bytes, so it needs its own
	// "key is empty" error rather than the misleading length one; it
	// is listed separately because the echo check below would pass
	// vacuously for "".
	t.Run("empty", func(t *testing.T) {
		_, err := crypto.ParseKey("  \n")
		if err == nil {
			t.Fatal("ParseKey(whitespace) succeeded, want error")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("ParseKey(whitespace) error = %q, want it to say the key is empty", err.Error())
		}
	})

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := crypto.ParseKey(input)
			if err == nil {
				t.Fatalf("ParseKey(%q) succeeded, want error", input)
			}
			if strings.Contains(err.Error(), input) {
				t.Fatalf("ParseKey error %q echoes the input %q", err.Error(), input)
			}
		})
	}
}

func TestParseKeyTrimsWhitespace(t *testing.T) {
	_, pub := testvectors.ControllerKey()
	s := "  " + crypto.Key(pub).String() + "\n"

	got, err := crypto.ParseKey(s)
	if err != nil {
		t.Fatalf("ParseKey(padded): %v", err)
	}
	if got != crypto.Key(pub) {
		t.Fatalf("ParseKey(padded) = %s, want %s", got, crypto.Key(pub))
	}
}

package testvectors

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// deriveKeyPair derives a Curve25519 key pair from a seed string.
// The private key is SHA-256 of the seed, clamped as X25519 requires.
func deriveKeyPair(t *testing.T, seed string) (priv, pub [32]byte) {
	t.Helper()

	priv = sha256.Sum256([]byte(seed))
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519(%q): %v", seed, err)
	}
	copy(pub[:], pubSlice)
	return priv, pub
}

func TestCanonicalMatchesBundle(t *testing.T) {
	var bundle map[string]any
	if err := json.Unmarshal(BundleJSON(), &bundle); err != nil {
		t.Fatalf("unmarshal bundle.json: %v", err)
	}
	delete(bundle, "timestamp")

	got, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle without timestamp: %v", err)
	}

	want := CanonicalJSON()

	if !bytes.Equal(got, want) {
		t.Fatalf("canonical.json does not match bundle.json without timestamp\n got: %s\nwant: %s", got, want)
	}
}

func TestDhtKeyMatchesVector(t *testing.T) {
	sum := sha1.Sum([]byte("test-ns" + "/" + "alpha"))
	want := hex.EncodeToString(sum[:])

	got := DHTKey()
	if got != want {
		t.Fatalf("dhtkey.txt = %q, want %q", got, want)
	}
}

func TestKeyPairsMatchVectors(t *testing.T) {
	cases := []struct {
		name   string
		seed   string
		loader func() (priv, pub [32]byte)
	}{
		{"controller", "stunmesh-provisioner-test-controller", ControllerKey},
		{"node", "stunmesh-provisioner-test-node", NodeKey},
		{"tunnel", "stunmesh-provisioner-test-tunnel", TunnelKey},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantPriv, wantPub := deriveKeyPair(t, c.seed)
			gotPriv, gotPub := c.loader()

			if gotPriv != wantPriv {
				t.Errorf("%s private key = %x, want %x", c.name, gotPriv, wantPriv)
			}
			if gotPub != wantPub {
				t.Errorf("%s public key = %x, want %x", c.name, gotPub, wantPub)
			}
		})
	}
}

func TestKeyFilesDecodeTo32Bytes(t *testing.T) {
	loaders := []struct {
		name   string
		loader func() (priv, pub [32]byte)
	}{
		{"controller", ControllerKey},
		{"node", NodeKey},
		{"tunnel", TunnelKey},
	}

	for _, l := range loaders {
		t.Run(l.name, func(t *testing.T) {
			priv, pub := l.loader()
			if len(priv) != 32 {
				t.Fatalf("%s private key is %d bytes, want 32", l.name, len(priv))
			}
			if len(pub) != 32 {
				t.Fatalf("%s public key is %d bytes, want 32", l.name, len(pub))
			}
		})
	}
}

func TestDecodeKeyPanicDoesNotLeakInput(t *testing.T) {
	const marker = "SECRET-MARKER-DO-NOT-LEAK-0123456789!!!not-valid-base64!!!"

	msg := func() (m string) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("DecodeKey: want panic for malformed input, got none")
			}
			m = fmt.Sprint(r)
		}()
		DecodeKey(marker)
		return ""
	}()

	if strings.Contains(msg, marker) {
		t.Fatalf("DecodeKey panic message contains the input value: %q", msg)
	}
}

func TestDirContainsExpectedFiles(t *testing.T) {
	want := []string{
		"controller.key", "controller.pub",
		"node.key", "node.pub",
		"tunnel.key", "tunnel.pub",
		"bundle.json", "canonical.json", "dhtkey.txt", "ciphertext.b64", "README.md",
	}

	for _, name := range want {
		path := Dir() + "/" + name
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected file %s in %s: %v", name, Dir(), err)
		}
	}
}

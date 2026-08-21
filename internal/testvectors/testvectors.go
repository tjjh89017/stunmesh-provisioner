// Package testvectors loads the golden test vectors under the repo-root
// testdata directory.
//
// It is a test helper only. Do not import it from production code.
// Every loader panics on an I/O or decode error. It names the failing
// file in the panic message.
package testvectors

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Dir returns the absolute path of the repo-root testdata directory.
func Dir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("testvectors: cannot determine caller for Dir()")
	}

	// thisFile is .../internal/testvectors/testvectors.go.
	// The repo root is two levels up.
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	return filepath.Join(root, "testdata")
}

// DecodeKey decodes a standard base64 WireGuard key. It panics if the
// input is not valid base64 or does not decode to 32 bytes. The panic
// message never includes the input or the decoded bytes: the input
// may be, or decode to, a private key.
func DecodeKey(b64 string) [32]byte {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(fmt.Sprintf("testvectors: decode key: invalid base64: %v", err))
	}
	if len(decoded) != 32 {
		panic(fmt.Sprintf("testvectors: key decodes to %d bytes, want 32", len(decoded)))
	}

	var out [32]byte
	copy(out[:], decoded)
	return out
}

// readFile reads a file under Dir(). It panics, naming the file, on
// any error.
func readFile(name string) []byte {
	path := filepath.Join(Dir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("testvectors: read %s: %v", name, err))
	}
	return data
}

// readTrimmed reads a file under Dir() and trims a trailing newline.
func readTrimmed(name string) string {
	return string(bytes.TrimRight(readFile(name), "\n"))
}

// readKeyPair reads a private/public key pair from the named files
// under Dir().
func readKeyPair(privFile, pubFile string) (priv, pub [32]byte) {
	priv = DecodeKey(readTrimmed(privFile))
	pub = DecodeKey(readTrimmed(pubFile))
	return priv, pub
}

// ControllerKey returns the controller test key pair.
func ControllerKey() (priv, pub [32]byte) {
	return readKeyPair("controller.key", "controller.pub")
}

// NodeKey returns the node test key pair.
func NodeKey() (priv, pub [32]byte) {
	return readKeyPair("node.key", "node.pub")
}

// TunnelKey returns the tunnel test key pair.
func TunnelKey() (priv, pub [32]byte) {
	return readKeyPair("tunnel.key", "tunnel.pub")
}

// BundleJSON returns the raw contents of bundle.json.
func BundleJSON() []byte {
	return readFile("bundle.json")
}

// CanonicalJSON returns the contents of canonical.json with the
// trailing newline trimmed.
func CanonicalJSON() []byte {
	return bytes.TrimRight(readFile("canonical.json"), "\n")
}

// DHTKey returns the trimmed contents of dhtkey.txt.
func DHTKey() string {
	return readTrimmed("dhtkey.txt")
}

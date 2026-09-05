// Package crypto provides authenticated encryption for the DHT
// bundle value (docs/format.md 4).
//
// The wire format of a sealed value is:
//
//	nonce(24) || ciphertext
//
// ciphertext is the output of golang.org/x/crypto/nacl/box.Seal
// (Curve25519 + XSalsa20-Poly1305). The controller is the sender: it
// seals with its own private key and the node's identity public key.
// The node is the recipient: it opens with its own identity private
// key and the controller's public key (docs/format.md 4). box
// gives confidentiality and sender authentication together, so no
// separate signature is needed.
//
// Open failing means one of: wrong recipient key, wrong sender key,
// or a corrupted/tampered ciphertext. The three cases are not
// distinguished on purpose -- telling them apart would hand an
// attacker an oracle to probe keys with.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Key is a Curve25519 key, public or private, in raw 32-byte form.
type Key [32]byte

// nonceSize is the length in bytes of the nacl/box nonce.
const nonceSize = 24

// ErrDecrypt is returned by Open when the sealed input cannot be
// authenticated and decrypted. The cause -- wrong key or tampered
// ciphertext -- is deliberately not distinguished in the error.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Keygen generates a new Curve25519 key pair using crypto/rand.
func Keygen() (priv, pub Key, err error) {
	pubPtr, privPtr, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, Key{}, err
	}
	return Key(*privPtr), Key(*pubPtr), nil
}

// ParseKey decodes s, a standard base64 (with padding) encoding of a
// 32-byte key, in the form WireGuard uses for its own keys.
// Surrounding whitespace is trimmed before decoding. It returns an
// error if s is not valid base64 or does not decode to exactly 32
// bytes. The error text never includes s.
func ParseKey(s string) (Key, error) {
	trimmed := strings.TrimSpace(s)

	// The empty string is valid base64 for zero bytes, so without this
	// check it would fall through to the length error, which reads as
	// "your key has the wrong size" when the caller in fact supplied no
	// key at all.
	if trimmed == "" {
		return Key{}, errors.New("crypto: key is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return Key{}, errors.New("crypto: key is not valid base64")
	}
	if len(decoded) != 32 {
		return Key{}, errors.New("crypto: key must decode to 32 bytes")
	}

	var k Key
	copy(k[:], decoded)
	return k, nil
}

// String returns the standard base64 (with padding) form of k, in
// the form WireGuard uses for its own keys. This form is safe to log
// or display for public keys. Callers must never log or display the
// String of a private key.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Public derives the Curve25519 public key that corresponds to the
// private key priv.
func Public(priv Key) Key {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		// X25519 against the standard basepoint fails only for a
		// scalar that produces a degenerate (low-order) result,
		// which does not happen for keys produced by Keygen or
		// ParseKey on real data. Treat it as a programmer error.
		panic("crypto: Public: " + err.Error())
	}

	var out Key
	copy(out[:], pub)
	return out
}

// Seal encrypts and authenticates plain for recipientPub, signed as
// coming from senderPriv, and returns nonce || ciphertext. The nonce
// is chosen at random for every call, so sealing the same plaintext
// twice yields different output.
func Seal(plain []byte, recipientPub, senderPriv Key) ([]byte, error) {
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return sealWithNonce(plain, &nonce, recipientPub, senderPriv), nil
}

// sealWithNonce is the shared implementation behind Seal and the
// test-only SealWithNonce (see export_test.go).
func sealWithNonce(plain []byte, nonce *[nonceSize]byte, recipientPub, senderPriv Key) []byte {
	pub := [32]byte(recipientPub)
	priv := [32]byte(senderPriv)
	return box.Seal(nonce[:], plain, nonce, &pub, &priv)
}

// Open authenticates and decrypts sealed, a value produced by Seal
// (or SealWithNonce) with recipient recipientPriv and sender
// senderPub. It returns ErrDecrypt if sealed is too short, was sealed
// with a different key pair, or has been tampered with.
func Open(sealed []byte, senderPub, recipientPriv Key) ([]byte, error) {
	if len(sealed) < nonceSize {
		return nil, ErrDecrypt
	}

	var nonce [nonceSize]byte
	copy(nonce[:], sealed[:nonceSize])

	pub := [32]byte(senderPub)
	priv := [32]byte(recipientPriv)

	plain, ok := box.Open(nil, sealed[nonceSize:], &nonce, &pub, &priv)
	if !ok {
		return nil, ErrDecrypt
	}
	return plain, nil
}

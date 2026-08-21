package crypto

// SealWithNonce seals plain like Seal, but with a caller-supplied
// nonce instead of a random one.
//
// It exists only so tests can reproduce a fixed golden ciphertext
// deterministically. Production code must always use Seal: a fixed
// or reused nonce breaks the confidentiality guarantee of box.
func SealWithNonce(plain []byte, nonce *[24]byte, recipientPub, senderPriv Key) []byte {
	return sealWithNonce(plain, nonce, recipientPub, senderPriv)
}

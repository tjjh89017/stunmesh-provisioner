// Package dhtkey computes the DHT key that names a node's record.
//
// The key is the lowercase hex SHA-1 digest of the namespace and the
// node ID joined by one "/" character: SHA1(namespace + "/" + nodeID).
// The namespace separates deployments so the key is hard to guess. The
// node ID picks one node inside a deployment.
//
// Neither namespace nor nodeID may contain "/". Without that rule the
// pairs ("a", "b/c") and ("a/b", "c") would join to the same string
// and collide on the same key.
package dhtkey

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

// Key returns the DHT key for the given namespace and node ID.
//
// It returns an error if namespace or nodeID is empty, or if either
// contains "/".
func Key(namespace, nodeID string) (string, error) {
	if err := validatePart("namespace", namespace); err != nil {
		return "", err
	}
	if err := validatePart("node_id", nodeID); err != nil {
		return "", err
	}

	sum := sha1.Sum([]byte(namespace + "/" + nodeID))
	return hex.EncodeToString(sum[:]), nil
}

// validatePart checks one input to Key. name identifies the parameter
// in the returned error; it must not be the value itself, since the
// value is part of a rendezvous secret.
func validatePart(name, value string) error {
	if value == "" {
		return errors.New("dhtkey: " + name + " must not be empty")
	}
	if strings.Contains(value, "/") {
		return errors.New("dhtkey: " + name + " must not contain '/'")
	}
	return nil
}

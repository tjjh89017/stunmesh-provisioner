//go:build embedca

package main

// The embedded Mozilla roots activate only when the system provides no
// certificate store. The agent reaches the dhtproxy over HTTPS, so this
// keeps a node working on an image without ca-bundle, and stays inert on
// one that has it.
import _ "golang.org/x/crypto/x509roots/fallback"

//go:build embedca

package main

// See cmd/stunmesh-agent/embedca.go. The controller reaches the same
// proxies over HTTPS, so it embeds the same fallback roots for a minimal
// container image with no certificate store.
import _ "golang.org/x/crypto/x509roots/fallback"

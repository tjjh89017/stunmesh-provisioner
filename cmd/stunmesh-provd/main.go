// Command stunmesh-provd is the controller. It publishes encrypted
// WireGuard and stunmesh-go config bundles to OpenDHT via dhtproxy.
package main

import "fmt"

// version is the build version. Set it via -ldflags at build time.
var version = "dev"

func main() {
	fmt.Printf("stunmesh-provd %s\n", version)
}

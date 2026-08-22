// Command stunmesh-provd is the controller. It publishes encrypted
// WireGuard and stunmesh-go config bundles to OpenDHT via dhtproxy.
package main

import "os"

// version is the build version. Set it via -ldflags at build time.
var version = "dev"

// main only forwards the process arguments and streams to Run and
// exits with the code it returns. All real logic lives in Run so it
// stays testable with fake args and buffers.
func main() {
	os.Exit(Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}

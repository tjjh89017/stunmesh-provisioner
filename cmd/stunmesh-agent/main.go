// Command stunmesh-agent runs on OpenWrt. It fetches, decrypts, and
// applies config bundles published by stunmesh-provd.
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

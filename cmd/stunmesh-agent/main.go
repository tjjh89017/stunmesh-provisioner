// Command stunmesh-agent runs on OpenWrt. It fetches, decrypts, and
// applies config bundles published by stunmesh-provd.
package main

import "fmt"

// version is the build version. Set it via -ldflags at build time.
var version = "dev"

func main() {
	fmt.Printf("stunmesh-agent %s\n", version)
}

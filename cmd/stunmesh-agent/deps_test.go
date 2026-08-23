package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoYAMLOrUCILibrary pins the stage3 acceptance condition: "The
// binary imports no YAML and no UCI library" (.plan/stage3-agent.md).
// A source grep is not proof, because a dependency could pull one in
// transitively. This test asks the Go toolchain for the full,
// resolved dependency graph of the agent's own main package and
// checks every import path in it, so it still holds if a future
// change adds an indirect dependency that happens to import YAML or a
// UCI binding.
//
// "No UCI library" means no library that talks to UCI itself (a cgo
// binding, or a package that shells out to the uci tool). It does not
// forbid this repository's own internal/uci package: that package
// only builds command argument lists in memory (see
// internal/uci/batch.go); the real "uci" binary runs through the
// exec interface (PLAN.md 6, stage3-agent.md item 9), and this test
// allows that one in-module package by exact path.
func TestNoYAMLOrUCILibrary(t *testing.T) {
	const ownUCIPackage = "github.com/tjjh89017/stunmesh-provisioner/internal/uci"

	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}

	for _, dep := range strings.Fields(string(out)) {
		lower := strings.ToLower(dep)

		if strings.Contains(lower, "yaml") {
			t.Errorf("agent binary depends on a YAML package: %s", dep)
		}

		if strings.Contains(lower, "uci") && dep != ownUCIPackage {
			t.Errorf("agent binary depends on a UCI library other than its own command builder: %s", dep)
		}
	}
}

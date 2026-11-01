package main

import (
	"slices"
	"testing"

	"github.com/tjjh89017/stunmesh-go/pluginapi"
)

func TestBuiltinPluginsRegistered(t *testing.T) {
	got := pluginapi.Registered()
	for _, name := range []string{"opendht", "cloudflare"} {
		if !slices.Contains(got, name) {
			t.Errorf("builtin plugin %q not registered; got %v", name, got)
		}
	}
}

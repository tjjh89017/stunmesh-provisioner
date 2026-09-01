package main

import (
	"context"

	stunmeshapp "github.com/tjjh89017/stunmesh-go/app"
)

// embeddedApp is the subset of *stunmeshapp.App the daemon and
// --oneshot/--stunmesh-only modes use. It exists so a test can
// substitute a fake through Env.NewApp instead of wiring a real
// stunmesh-go config and its WireGuard/STUN dependencies.
type embeddedApp interface {
	Run(ctx context.Context) error
	RunOneshot(ctx context.Context) error
	Close()
}

// newEmbeddedApp is Env.NewApp's default: build the real, fully wired
// stunmesh-go app (see the vendored app.App's doc comment). A real
// run leaves Env.NewApp nil and gets this; a test sets Env.NewApp to
// return a fake.
func newEmbeddedApp(opts stunmeshapp.Options) (embeddedApp, error) {
	return stunmeshapp.New(opts)
}

// appFactoryFor returns env.NewApp, or newEmbeddedApp when env.NewApp
// is nil, mirroring runnerFor's pattern in fetch_apply.go for
// execx.Runner.
func appFactoryFor(env *Env) func(stunmeshapp.Options) (embeddedApp, error) {
	if env.NewApp != nil {
		return env.NewApp
	}
	return newEmbeddedApp
}

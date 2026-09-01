package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	stunmeshapp "github.com/tjjh89017/stunmesh-go/app"
	"github.com/tjjh89017/stunmesh-provisioner/internal/last"
)

// fakeEmbeddedApp is a minimal embeddedApp for daemon.go's tests: it
// counts calls and lets a test block Run until the test releases it,
// so a test can assert the daemon actually waits for Run to return
// before calling Close (embeddedRunner.stop's contract).
type fakeEmbeddedApp struct {
	runCalls    int32
	oneshotErr  error
	oneshotCall int32
	closeCalls  int32
}

func (f *fakeEmbeddedApp) Run(ctx context.Context) error {
	atomic.AddInt32(&f.runCalls, 1)
	<-ctx.Done()
	return nil
}

func (f *fakeEmbeddedApp) RunOneshot(ctx context.Context) error {
	atomic.AddInt32(&f.oneshotCall, 1)
	return f.oneshotErr
}

func (f *fakeEmbeddedApp) Close() {
	atomic.AddInt32(&f.closeCalls, 1)
}

func fakeAppFactory(apps *[]*fakeEmbeddedApp, mu *sync.Mutex) func(stunmeshapp.Options) (embeddedApp, error) {
	return func(stunmeshapp.Options) (embeddedApp, error) {
		mu.Lock()
		defer mu.Unlock()
		a := &fakeEmbeddedApp{}
		*apps = append(*apps, a)
		return a, nil
	}
}

func TestNeedsEmbeddedRun(t *testing.T) {
	cases := []struct {
		name string
		diff *Diff
		want bool
	}{
		{"nil diff", nil, false},
		{"stunmesh empty", &Diff{Stunmesh: StunmeshEmpty}, false},
		{"stunmesh changed", &Diff{Stunmesh: StunmeshChanged}, true},
		{
			"interface changed, stunmesh unchanged",
			&Diff{Stunmesh: StunmeshUnchanged, Interfaces: []InterfaceDiff{{Name: "wg0", Change: InterfaceNew}}},
			true,
		},
		{
			"nothing changed",
			&Diff{Stunmesh: StunmeshUnchanged, Interfaces: []InterfaceDiff{{Name: "wg0", Change: InterfaceUnchanged}}},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := needsEmbeddedRun(c.diff); got != c.want {
				t.Errorf("needsEmbeddedRun(%+v) = %v, want %v", c.diff, got, c.want)
			}
		})
	}
}

func TestStartEmbedded_StopWaitsForRunThenCloses(t *testing.T) {
	var mu sync.Mutex
	var apps []*fakeEmbeddedApp
	factory := fakeAppFactory(&apps, &mu)

	var stderr bytes.Buffer
	r, err := startEmbedded(factory, stunmeshapp.Options{}, &stderr)
	if err != nil {
		t.Fatalf("startEmbedded: %v", err)
	}

	// Give the goroutine a moment to actually call Run.
	deadline := time.Now().Add(time.Second)
	for atomic.LoadInt32(&apps[0].runCalls) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run was never called")
		}
		time.Sleep(time.Millisecond)
	}

	r.stop()

	if atomic.LoadInt32(&apps[0].closeCalls) != 1 {
		t.Errorf("closeCalls = %d, want 1", apps[0].closeCalls)
	}
}

func TestReconcileEmbedded_StunmeshEmptyStopsAndReturnsNil(t *testing.T) {
	var mu sync.Mutex
	var apps []*fakeEmbeddedApp
	factory := fakeAppFactory(&apps, &mu)

	var stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &bytes.Buffer{}, &stderr)

	cur, err := startEmbedded(factory, stunmeshapp.Options{}, &stderr)
	if err != nil {
		t.Fatalf("startEmbedded: %v", err)
	}

	diff := &Diff{Stunmesh: StunmeshEmpty}
	got := reconcileEmbedded(env, factory, &Config{}, cur, diff, false)
	if got != nil {
		t.Errorf("got %+v, want nil (nothing should be running)", got)
	}
	if atomic.LoadInt32(&apps[0].closeCalls) != 1 {
		t.Errorf("closeCalls = %d, want 1 (old instance stopped)", apps[0].closeCalls)
	}
}

func TestReconcileEmbedded_NoActionWhenNothingChanged(t *testing.T) {
	var mu sync.Mutex
	var apps []*fakeEmbeddedApp
	factory := fakeAppFactory(&apps, &mu)
	var stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &bytes.Buffer{}, &stderr)

	diff := &Diff{Stunmesh: StunmeshUnchanged, Interfaces: []InterfaceDiff{{Name: "wg0", Change: InterfaceUnchanged}}}
	got := reconcileEmbedded(env, factory, &Config{}, nil, diff, false)
	if got != nil {
		t.Errorf("got %+v, want nil (no action taken, cur was already nil)", got)
	}
	if len(apps) != 0 {
		t.Errorf("factory was called %d times, want 0", len(apps))
	}
}

func TestReconcileEmbedded_ForceStartFallsBackToLastJSON(t *testing.T) {
	dir := t.TempDir()
	lastPath := dir + "/last.json"
	if err := last.Write(lastPath, &last.State{Version: last.CurrentVersion, WG: map[string]last.Interface{}, Stunmesh: "some config"}); err != nil {
		t.Fatalf("last.Write: %v", err)
	}

	var mu sync.Mutex
	var apps []*fakeEmbeddedApp
	factory := fakeAppFactory(&apps, &mu)
	var stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &bytes.Buffer{}, &stderr)

	cfg := &Config{LastPath: lastPath}
	got := reconcileEmbedded(env, factory, cfg, nil, nil, true)
	if got == nil {
		t.Fatal("got nil, want a running instance (last.json records a non-empty stunmesh text)")
	}
	if len(apps) != 1 {
		t.Errorf("factory called %d times, want 1", len(apps))
	}
	got.stop()
}

func TestRunOneshot_NoValueIsExitOK(t *testing.T) {
	// No DHT reachable at all (a bogus proxy URL that always errors),
	// so runFetchApply's "get" call fails -- runOneshot must exit
	// ExitError, not hang or panic, and must never call the embedded
	// app factory (nothing was applied).
	cfg, _, _ := fetchTestConfig(t, t.TempDir()+"/agent.lock", []string{"http://127.0.0.1:1"})
	var mu sync.Mutex
	var apps []*fakeEmbeddedApp
	var stdout, stderr bytes.Buffer
	env := newEnv(strings.NewReader(""), &stdout, &stderr)
	env.NewApp = fakeAppFactory(&apps, &mu)

	code := runOneshot(env, cfg)
	if code != ExitError {
		t.Errorf("code = %d, want %d; stderr=%q", code, ExitError, stderr.String())
	}
	if len(apps) != 0 {
		t.Errorf("embedded app factory called %d times, want 0", len(apps))
	}
}

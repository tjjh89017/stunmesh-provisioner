package execx_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tjjh89017/stunmesh-provisioner/internal/execx"
)

func TestFake_RecordsCalls_ExactSequence(t *testing.T) {
	f := execx.NewFake()

	_, _ = f.Run("uci", "set", "network.wan.proto=wireguard")
	_, _ = f.Run("uci", "commit", "network")
	_, _ = f.Run("ubus", "call", "network", "reload")

	want := []execx.Call{
		{Name: "uci", Args: []string{"set", "network.wan.proto=wireguard"}},
		{Name: "uci", Args: []string{"commit", "network"}},
		{Name: "ubus", Args: []string{"call", "network", "reload"}},
	}
	if got := f.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestFake_ScriptedResults(t *testing.T) {
	boom := errors.New("boom")
	f := execx.NewFake(
		execx.Result{Stdout: "first-out"},
		execx.Result{Err: boom},
	)

	stdout, err := f.Run("uci", "get", "network.wan")
	if err != nil || stdout != "first-out" {
		t.Errorf("call 1: got (%q, %v), want (%q, nil)", stdout, err, "first-out")
	}

	stdout, err = f.Run("uci", "commit", "network")
	if !errors.Is(err, boom) || stdout != "" {
		t.Errorf("call 2: got (%q, %v), want (\"\", boom)", stdout, err)
	}

	// A call beyond the scripted results defaults to success.
	stdout, err = f.Run("ubus", "call", "network", "reload")
	if err != nil || stdout != "" {
		t.Errorf("call 3 (unscripted): got (%q, %v), want (\"\", nil)", stdout, err)
	}
}

func TestFake_Run_CopiesArgs(t *testing.T) {
	f := execx.NewFake()

	args := []string{"a", "b"}
	_, _ = f.Run("cmd", args...)
	args[0] = "mutated"

	want := []execx.Call{{Name: "cmd", Args: []string{"a", "b"}}}
	if got := f.Calls(); !reflect.DeepEqual(got, want) {
		t.Errorf("Calls() = %+v, want %+v (recorded args must not alias the caller's slice)", got, want)
	}
}

func TestFake_Calls_ReturnsCopy(t *testing.T) {
	f := execx.NewFake()
	_, _ = f.Run("cmd", "x")

	got := f.Calls()
	got[0].Name = "mutated"

	if f.Calls()[0].Name != "cmd" {
		t.Error("mutating the slice returned by Calls() affected the fake's internal state")
	}
}

// Fake must implement Runner.
var _ execx.Runner = execx.NewFake()

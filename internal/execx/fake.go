package execx

import "sync"

// Call is one recorded invocation of Fake.Run.
type Call struct {
	// Name is the command name Run was called with.
	Name string
	// Args is the argument slice Run was called with.
	Args []string
}

// Result is the scripted return value for one Fake.Run call: the
// stdout Run returns, the error Run returns, or both.
type Result struct {
	Stdout string
	Err    error
}

// Fake is a Runner for tests. It never runs a real command. It
// records every call, in order, and returns a scripted Result for
// each one.
//
// # Scripting
//
// NewFake takes the scripted Results in call order: the first Run
// call returns results[0], the second returns results[1], and so on.
// A call past the end of results defaults to success: it returns ""
// and a nil error. This lets a test script only the calls it cares
// about and leave the rest at the default.
//
// # Exact-sequence assertions
//
// Calls returns every recorded Call, in order. A test builds the
// expected sequence as a []Call literal and compares it with
// reflect.DeepEqual:
//
//	f := execx.NewFake()
//	// ... code under test runs f.Run(...) some number of times ...
//	want := []execx.Call{
//		{Name: "uci", Args: []string{"set", "network.wan.proto=wireguard"}},
//		{Name: "uci", Args: []string{"commit", "network"}},
//		{Name: "ubus", Args: []string{"call", "network", "reload"}},
//	}
//	if got := f.Calls(); !reflect.DeepEqual(got, want) {
//		t.Errorf("Calls() =\n%+v\nwant\n%+v", got, want)
//	}
//
// A Fake is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	results []Result
	calls   []Call
}

// NewFake returns a Fake scripted with results, in call order. See
// the Fake doc "Scripting" section.
func NewFake(results ...Result) *Fake {
	return &Fake{results: append([]Result(nil), results...)}
}

// Run implements Runner. It records the call and returns the next
// scripted Result, or a default success if none is left.
func (f *Fake) Run(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, Call{
		Name: name,
		Args: append([]string(nil), args...),
	})

	i := len(f.calls) - 1
	if i < len(f.results) {
		r := f.results[i]
		return r.Stdout, r.Err
	}
	return "", nil
}

// Calls returns every call recorded so far, in the order Run was
// called. The returned slice is a copy; modifying it does not affect
// the Fake.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()

	calls := make([]Call, len(f.calls))
	copy(calls, f.calls)
	return calls
}

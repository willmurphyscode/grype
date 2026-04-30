package gonative

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/anchore/grype/grype/db/provider"
)

// reset is a test-local alias for ResetForTesting so call sites stay short.
var reset = ResetForTesting

type fakeProvider struct {
	id     provider.Identifier
	called bool
}

func (f *fakeProvider) ID() provider.Identifier         { return f.id }
func (f *fakeProvider) State() (*provider.State, error) { return nil, nil }
func (f *fakeProvider) Update(_ context.Context) error  { f.called = true; return nil }

func TestRegisterAndLookup(t *testing.T) {
	reset()

	want := &fakeProvider{id: provider.Identifier{Name: "alpha", Kind: Kind}}
	Register("alpha", func(_ string, id provider.Identifier, _ any) (provider.Reader, error) {
		want.id = id
		return want, nil
	})

	got, ok := Lookup("alpha")
	if !ok {
		t.Fatalf("expected alpha to be registered")
	}
	p, err := got("/data", provider.Identifier{Name: "alpha", Kind: Kind}, nil)
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}
	if p.ID().Name != "alpha" {
		t.Fatalf("expected provider name %q, got %q", "alpha", p.ID().Name)
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	reset()
	f := func(_ string, _ provider.Identifier, _ any) (provider.Reader, error) { return nil, nil }
	Register("dup", f)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected panic on duplicate registration")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "already registered") {
			t.Fatalf("expected duplicate-registration panic, got: %v", r)
		}
	}()
	Register("dup", f)
}

func TestNewProviderUnregistered(t *testing.T) {
	reset()

	_, err := NewProvider("/data", provider.Identifier{Name: "missing", Kind: Kind}, nil)
	if err == nil {
		t.Fatalf("expected error for unregistered provider")
	}
	if !strings.Contains(err.Error(), `"missing"`) {
		t.Fatalf("error should name the missing provider, got: %v", err)
	}
}

func TestRegistryConcurrency(t *testing.T) {
	reset()

	// Sanity-check that concurrent Lookups don't race against Register.
	var wg sync.WaitGroup
	wg.Add(1)
	Register("a", func(_ string, _ provider.Identifier, _ any) (provider.Reader, error) {
		return &fakeProvider{}, nil
	})

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, ok := Lookup("a"); !ok {
				t.Errorf("lookup %d failed", i)
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		_ = Names()
	}
	wg.Wait()
}

func TestNamesSorted(t *testing.T) {
	reset()
	for _, n := range []string{"charlie", "alpha", "bravo"} {
		Register(n, func(_ string, _ provider.Identifier, _ any) (provider.Reader, error) {
			return nil, errors.New("unused")
		})
	}
	got := Names()
	want := []string{"alpha", "bravo", "charlie"}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: %v vs %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("position %d: got %q want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

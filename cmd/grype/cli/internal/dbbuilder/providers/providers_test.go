package providers

import (
	"context"
	"sync"
	"testing"

	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers/gonative"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers/vunnel"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/pull"
	"github.com/anchore/grype/grype/db/provider"
)

// gonative registry is process-global; serialize tests that touch it.
var registryMu sync.Mutex

type fakeGoProvider struct{ id provider.Identifier }

func (f *fakeGoProvider) ID() provider.Identifier         { return f.id }
func (f *fakeGoProvider) State() (*provider.State, error) { return nil, nil }
func (f *fakeGoProvider) Update(_ context.Context) error  { return nil }

func TestDispatch_PerProviderExecutorGo(t *testing.T) {
	registryMu.Lock()
	defer registryMu.Unlock()
	gonative.ResetForTesting()

	gonative.Register("alpha", func(_ string, id provider.Identifier, _ any) (provider.Reader, error) {
		return &fakeGoProvider{id: id}, nil
	})

	ps, err := New(t.TempDir(), vunnel.Config{Executor: vunnel.ExecutorDocker, DockerImage: "x", DockerTag: "y"},
		pull.ProviderRunConfig{
			Identifier: provider.Identifier{Name: "alpha"},
			Executor:   ExecutorGo,
		},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(ps) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(ps))
	}
	if _, ok := ps[0].(*fakeGoProvider); !ok {
		t.Fatalf("expected gonative dispatch, got %T", ps[0])
	}
	if ps[0].ID().Name != "alpha" {
		t.Fatalf("expected id alpha, got %q", ps[0].ID().Name)
	}
	if ps[0].ID().Kind != gonative.Kind {
		t.Fatalf("expected kind %q, got %q", gonative.Kind, ps[0].ID().Kind)
	}
}

func TestDispatch_DefaultExecutorFallsBackToVunnel(t *testing.T) {
	// No executor set on the per-provider config and no gonative registration —
	// should pick the vunnel runner with the global Config (docker-vunnel for
	// dev). We just check the kind on the returned provider's identifier.
	ps, err := New(t.TempDir(), vunnel.Config{Executor: vunnel.ExecutorDocker, DockerImage: "x", DockerTag: "y"},
		pull.ProviderRunConfig{
			Identifier: provider.Identifier{Name: "bravo", Kind: vunnel.Kind},
		},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(ps) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(ps))
	}
	if ps[0].ID().Kind != vunnel.Kind {
		t.Fatalf("expected vunnel dispatch, got kind %q", ps[0].ID().Kind)
	}
}

func TestDispatch_UnknownKind(t *testing.T) {
	_, err := New(t.TempDir(), vunnel.Config{},
		pull.ProviderRunConfig{
			Identifier: provider.Identifier{Name: "charlie", Kind: "bogus"},
		},
	)
	if err == nil {
		t.Fatalf("expected error for unknown kind")
	}
}

func TestDispatch_NoProviders(t *testing.T) {
	_, err := New(t.TempDir(), vunnel.Config{})
	if err != ErrNoProviders {
		t.Fatalf("expected ErrNoProviders, got %v", err)
	}
}

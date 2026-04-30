// Package gonative is the in-process executor for `grype db-builder pull`.
//
// The package ships with an empty registry — it is the seam through which
// vunnel providers can be incrementally re-implemented in Go without
// changing the db-builder pull/build pipeline. A provider opts in by adding a
// sub-package whose init() calls Register; per-provider config can then set
// `executor: go` to drive that provider in-process instead of shelling out
// to vunnel.
package gonative

import (
	"fmt"
	"sort"
	"sync"

	"github.com/anchore/grype/grype/db/provider"
)

// Kind is stamped onto identifiers when a provider is dispatched via the
// gonative executor.
const Kind provider.Kind = "gonative"

// Factory builds a provider.Reader (which should also satisfy provider.Writer
// so the pull loop can call Update) for the named provider. The provider's
// per-config block from db-builder config (an arbitrary mapstructure-decodable
// any) is passed through as cfg.
type Factory func(root string, id provider.Identifier, cfg any) (provider.Reader, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register binds a provider name to a Factory. Intended to be called from
// init() in a provider's sub-package. Re-registering the same name panics —
// the registry is process-global and double-registration is always a bug.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("gonative: provider %q already registered", name))
	}
	registry[name] = f
}

// Lookup returns the Factory for name, or false if no Go-native implementation
// is registered. Callers should fall back to the configured vunnel executor
// when this returns false.
func Lookup(name string) (Factory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	f, ok := registry[name]
	return f, ok
}

// Names returns every registered provider name in sorted order.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NewProvider resolves the registry entry for id.Name and constructs the
// provider. Returns an error (not panic) so the dispatcher can surface a
// helpful message when config asks for `executor: go` but no Go
// implementation has been wired up yet.
func NewProvider(root string, id provider.Identifier, cfg any) (provider.Reader, error) {
	f, ok := Lookup(id.Name)
	if !ok {
		return nil, fmt.Errorf("no go-native implementation registered for provider %q (available: %v)", id.Name, Names())
	}
	return f(root, id, cfg)
}

// ResetForTesting wipes the registry. Test-only — production code never has
// reason to deregister a provider, so this is intentionally separate from any
// public API surface.
func ResetForTesting() {
	mu.Lock()
	defer mu.Unlock()
	registry = map[string]Factory{}
}

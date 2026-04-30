// Package providers wires the per-provider config in the db-builder pull/build
// pipeline to a concrete executor. There are three executors today:
//
//   - vunnel + docker/podman: run vunnel inside a container (default for local
//     dev — only docker is required on the host)
//   - vunnel + local: invoke the vunnel binary on PATH
//   - gonative: invoke an in-process Go-native implementation registered in
//     the gonative package
//
// The executor for a given provider is chosen by the per-provider Executor
// field (`executor:` in YAML), falling back to the global vunnel.Executor when
// blank. The "go" executor short-circuits to the gonative registry; everything
// else is treated as a vunnel runner mode.
package providers

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers/external"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers/gonative"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers/vunnel"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/pull"
	"github.com/anchore/grype/grype/db/provider"
)

var ErrNoProviders = fmt.Errorf("no providers configured")

// ExecutorGo is the per-provider executor value that routes a provider to the
// gonative in-process registry.
const ExecutorGo = "go"

func New(root string, vCfg vunnel.Config, cfgs ...pull.ProviderRunConfig) (provider.Providers, error) {
	var providers []provider.Reader
	var eolProviders []provider.Reader

	if vCfg.GenerateConfigs {
		generatedCfgs, err := vunnel.GenerateConfigs(root, vCfg)
		if err != nil {
			return nil, fmt.Errorf("unable to generate vunnel providers: %w", err)
		}
		cfgs = append(cfgs, generatedCfgs...)
	}

	if len(cfgs) == 0 {
		return nil, ErrNoProviders
	}

	for _, cfg := range cfgs {
		p, err := newProvider(root, vCfg, cfg)
		if err != nil {
			return nil, err
		}
		switch p.ID().Name {
		case "nvd":
			// it is important that NVD is processed first since other providers depend on the severity information from these records
			providers = append([]provider.Reader{p}, providers...)
		case "eol":
			// EOL provider must run last since it needs OperatingSystem records to exist (created by other providers)
			eolProviders = append(eolProviders, p)
		default:
			providers = append(providers, p)
		}
	}

	// append EOL providers at the end
	providers = append(providers, eolProviders...)

	return providers, nil
}

func newProvider(root string, vCfg vunnel.Config, cfg pull.ProviderRunConfig) (provider.Reader, error) {
	// per-provider executor wins over the global vunnel executor; "go" is the
	// only value that routes outside the vunnel/external dispatch.
	if cfg.Executor == ExecutorGo {
		id := cfg.Identifier
		if id.Kind == "" {
			id.Kind = gonative.Kind
		}
		return gonative.NewProvider(root, id, cfg.Config)
	}

	switch cfg.Kind {
	case vunnel.Kind, "": // note: this is the default
		runCfg := vCfg
		if cfg.Executor != "" {
			runCfg.Executor = cfg.Executor
		}
		return vunnel.NewProvider(root, cfg.Identifier, runCfg), nil
	case external.Kind:
		var c external.Config
		if err := mapstructure.Decode(cfg.Config, &c); err != nil {
			return nil, fmt.Errorf("failed to decode external provider config: %w", err)
		}
		return external.NewProvider(root, cfg.Identifier, c), nil
	case gonative.Kind:
		// allow `kind: gonative` as an alternative to `executor: go`
		return gonative.NewProvider(root, cfg.Identifier, cfg.Config)
	default:
		return nil, fmt.Errorf("unknown provider kind %q", cfg.Kind)
	}
}

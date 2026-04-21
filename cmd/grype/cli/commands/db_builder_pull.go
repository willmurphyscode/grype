package commands

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers/vunnel"
	pullpkg "github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/pull"
	"github.com/anchore/grype/cmd/grype/cli/options"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type dbBuilderPullOptions struct {
	DBBuilder *options.DBBuilderConfig `yaml:"db-builder" json:"db-builder" mapstructure:"db-builder"`
}

var _ clio.FlagAdder = (*dbBuilderPullOptions)(nil)

func (o *dbBuilderPullOptions) AddFlags(flags clio.FlagSet) {
	flags.IntVarP(&o.DBBuilder.Pull.Parallelism,
		"parallelism", "",
		"number of vulnerability providers to update concurrently")

	flags.StringArrayVarP(&o.DBBuilder.Provider.IncludeFilter,
		"provider-name", "p",
		"one or more provider names to filter by (default: empty = all)")

	flags.BoolVarP(&o.DBBuilder.Provider.Vunnel.GenerateConfigs,
		"generate-providers-from-vunnel", "g",
		"generate provider configs from 'vunnel list' output")
}

func DBBuilderPull(app clio.Application) *cobra.Command {
	opts := &dbBuilderPullOptions{
		DBBuilder: options.DefaultDBBuilder(),
	}

	cmd := &cobra.Command{
		Use:     "pull",
		Short:   "pull and process all upstream vulnerability data via vunnel",
		Args:    cobra.NoArgs,
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDBBuilderPull(opts.DBBuilder)
		},
	}

	return app.SetupCommand(cmd, opts)
}

func runDBBuilderPull(cfg *options.DBBuilderConfig) error {
	ps, err := providers.New(cfg.Provider.Root, vunnelConfigFrom(cfg), cfg.Provider.Configs...)
	if err != nil {
		if errors.Is(err, providers.ErrNoProviders) {
			log.Error("configure a provider via the application config or use -g to generate a list of configs from vunnel")
		}
		return err
	}

	if len(cfg.Provider.IncludeFilter) > 0 {
		log.WithFields("keep-only", cfg.Provider.IncludeFilter).Debug("filtering providers by name")
		ps = ps.Filter(cfg.Provider.IncludeFilter...)
	}

	return pullpkg.Pull(pullpkg.Config{
		Parallelism: cfg.Pull.Parallelism,
		Collection: dbprovider.Collection{
			Root:      cfg.Provider.Root,
			Providers: ps,
		},
	})
}

func vunnelConfigFrom(cfg *options.DBBuilderConfig) vunnel.Config {
	return vunnel.Config{
		Config:           cfg.Provider.Vunnel.Config,
		Executor:         cfg.Provider.Vunnel.Executor,
		DockerImage:      cfg.Provider.Vunnel.DockerImage,
		DockerTag:        cfg.Provider.Vunnel.DockerTag,
		GenerateConfigs:  cfg.Provider.Vunnel.GenerateConfigs,
		ExcludeProviders: cfg.Provider.Vunnel.ExcludeProviders,
		Env:              cfg.Provider.Vunnel.Env,
	}
}

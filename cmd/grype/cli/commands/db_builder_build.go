package commands

import (
	"errors"
	"fmt"
	"os"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/providers"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/db"
	dbprovider "github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/internal/log"
)

type dbBuilderBuildOptions struct {
	DBBuilder *options.DBBuilderConfig `yaml:"db-builder" json:"db-builder" mapstructure:"db-builder"`
}

var _ clio.FlagAdder = (*dbBuilderBuildOptions)(nil)

func (o *dbBuilderBuildOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.DBBuilder.Build.Dir,
		"dir", "d",
		"directory where the database is written")

	flags.IntVarP(&o.DBBuilder.Build.SchemaVersion,
		"schema", "s",
		"DB schema version to build for")

	flags.IntVarP(&o.DBBuilder.Build.BatchSize,
		"batch-size", "",
		"number of database operations to batch before flushing to disk")

	flags.BoolVarP(&o.DBBuilder.Build.SkipValidation,
		"skip-validation", "",
		"skip validation of the provider state")

	flags.StringArrayVarP(&o.DBBuilder.Provider.IncludeFilter,
		"provider-name", "p",
		"one or more provider names to filter by (default: empty = all)")
}

func DBBuilderBuild(app clio.Application) *cobra.Command {
	opts := &dbBuilderBuildOptions{
		DBBuilder: options.DefaultDBBuilder(),
	}

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "build a SQLite DB from the vulnerability feeds data for a particular schema version",
		Args:    cobra.NoArgs,
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := validateCPEParts(opts.DBBuilder.Build.IncludeCPEParts); err != nil {
				return err
			}
			return runDBBuilderBuild(opts.DBBuilder)
		},
	}

	return app.SetupCommand(cmd, opts)
}

func validateCPEParts(parts []string) error {
	validParts := strset.New("a", "o", "h")
	for _, part := range parts {
		if !validParts.Has(part) {
			return fmt.Errorf("invalid CPE part: %s", part)
		}
	}
	if len(parts) == 0 {
		return errors.New("no CPE parts provided")
	}
	return nil
}

func runDBBuilderBuild(cfg *options.DBBuilderConfig) error {
	if _, err := os.Stat(cfg.Build.Dir); os.IsNotExist(err) {
		if err := os.MkdirAll(cfg.Build.Dir, 0o755); err != nil {
			return fmt.Errorf("unable to make db build dir: %w", err)
		}
	}

	ps, err := providers.New(cfg.Provider.Root, vunnelConfigFrom(cfg), cfg.Provider.Configs...)
	if err != nil {
		if errors.Is(err, providers.ErrNoProviders) {
			log.Error("configure a provider via the application config or use -g to generate a list of configs from vunnel")
		}
		return fmt.Errorf("unable to create providers: %w", err)
	}

	if len(cfg.Provider.IncludeFilter) > 0 {
		log.WithFields("keep-only", cfg.Provider.IncludeFilter).Debug("filtering providers by name")
		ps = ps.Filter(cfg.Provider.IncludeFilter...)
	}

	states, err := providerStates(cfg.Build.SkipValidation, ps)
	if err != nil {
		return fmt.Errorf("unable to get provider states: %w", err)
	}

	earliest, err := dbprovider.States(states).EarliestTimestamp()
	if err != nil {
		return fmt.Errorf("unable to get earliest timestamp: %w", err)
	}

	return db.Build(db.BuildConfig{
		SchemaVersion:        cfg.Build.SchemaVersion,
		Directory:            cfg.Build.Dir,
		States:               states,
		Timestamp:            earliest,
		IncludeCPEParts:      cfg.Build.IncludeCPEParts,
		InferNVDFixVersions:  cfg.Build.InferNVDFixVersions,
		Hydrate:              cfg.Build.Hydrate,
		FailOnMissingFixDate: cfg.Build.FailOnMissingFixDate,
		BatchSize:            cfg.Build.BatchSize,
	})
}

func providerStates(skipValidation bool, readers []dbprovider.Reader) ([]dbprovider.State, error) {
	log.Debug("reading all provider state")

	if len(readers) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	var states []dbprovider.State
	for _, p := range readers {
		log.WithFields("provider", p.ID().Name).Debug("reading state")

		sd, err := p.State()
		if err != nil {
			return nil, fmt.Errorf("unable to read provider state: %w", err)
		}

		if !skipValidation {
			log.WithFields("provider", p.ID().Name).Trace("validating state")
			if err := sd.Verify(); err != nil {
				return nil, fmt.Errorf("invalid provider state: %w", err)
			}
		}
		states = append(states, *sd)
	}
	if !skipValidation {
		log.Debug("state validated for all providers")
	}
	return states, nil
}

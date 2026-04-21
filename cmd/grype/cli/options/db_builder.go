package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/internal/dbbuilder/pull"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/internal/redact"
)

// DBBuilderConfig holds configuration for the `grype db-builder` subcommands. It nests under a
// single `db-builder:` key in the application config so it does not collide with the top-level
// `db:` stanza used by `grype db {check,update,import,list,search,...}`.
type DBBuilderConfig struct {
	Pull     DBBuilderPull     `yaml:"pull" json:"pull" mapstructure:"pull"`
	Build    DBBuilderBuild    `yaml:"build" json:"build" mapstructure:"build"`
	Cache    DBBuilderCache    `yaml:"cache" json:"cache" mapstructure:"cache"`
	Provider DBBuilderProvider `yaml:"provider" json:"provider" mapstructure:"provider"`
}

type DBBuilderPull struct {
	Parallelism int `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`
}

type DBBuilderBuild struct {
	Dir                  string   `yaml:"dir" json:"dir" mapstructure:"dir"`
	SchemaVersion        int      `yaml:"schema-version" json:"schema-version" mapstructure:"schema-version"`
	SkipValidation       bool     `yaml:"skip-validation" json:"skip-validation" mapstructure:"skip-validation"`
	BatchSize            int      `yaml:"batch-size" json:"batch-size" mapstructure:"batch-size"`
	IncludeCPEParts      []string `yaml:"include-cpe-parts" json:"include-cpe-parts" mapstructure:"include-cpe-parts"`
	InferNVDFixVersions  bool     `yaml:"infer-nvd-fix-versions" json:"infer-nvd-fix-versions" mapstructure:"infer-nvd-fix-versions"`
	Hydrate              bool     `yaml:"hydrate" json:"hydrate" mapstructure:"hydrate"`
	FailOnMissingFixDate bool     `yaml:"fail-on-missing-fix-date" json:"fail-on-missing-fix-date" mapstructure:"fail-on-missing-fix-date"`
}

type DBBuilderCache struct {
	Archive string                `yaml:"archive" json:"archive" mapstructure:"archive"`
	Restore DBBuilderCacheRestore `yaml:"restore" json:"restore" mapstructure:"restore"`
}

type DBBuilderCacheRestore struct {
	DeleteExisting bool `yaml:"delete-existing" json:"delete-existing" mapstructure:"delete-existing"`
}

type DBBuilderProvider struct {
	Root          string                   `yaml:"root" json:"root" mapstructure:"root"`
	IncludeFilter []string                 `yaml:"include-filter" json:"include-filter" mapstructure:"include-filter"`
	Vunnel        DBBuilderVunnel          `yaml:"vunnel" json:"vunnel" mapstructure:"vunnel"`
	Configs       []pull.ProviderRunConfig `yaml:"configs" json:"configs" mapstructure:"configs"`
}

type DBBuilderVunnel struct {
	Config           string   `yaml:"config" json:"config" mapstructure:"config"`
	Executor         string   `yaml:"executor" json:"executor" mapstructure:"executor"`
	DockerImage      string   `yaml:"docker-image" json:"docker-image" mapstructure:"docker-image"`
	DockerTag        string   `yaml:"docker-tag" json:"docker-tag" mapstructure:"docker-tag"`
	GenerateConfigs  bool     `yaml:"generate-configs" json:"generate-configs" mapstructure:"generate-configs"`
	ExcludeProviders []string `yaml:"exclude-providers" json:"exclude-providers" mapstructure:"exclude-providers"`
	// note: Env is read from config only — we don't want users to specify run env vars via app-level env vars.
	Env map[string]string `yaml:"env" json:"env" mapstructure:"-"`
}

var _ clio.PostLoader = (*DBBuilderConfig)(nil)

// DefaultDBBuilder returns a DBBuilderConfig populated with the same defaults that grype-db
// used to produce.
func DefaultDBBuilder() *DBBuilderConfig {
	return &DBBuilderConfig{
		Pull: DBBuilderPull{
			Parallelism: 4,
		},
		Build: DBBuilderBuild{
			Dir:                  "./build",
			SchemaVersion:        db.DefaultSchemaVersion,
			SkipValidation:       false,
			BatchSize:            db.DefaultBatchSize,
			IncludeCPEParts:      []string{"a", "h", "o"},
			InferNVDFixVersions:  true,
			Hydrate:              false,
			FailOnMissingFixDate: false,
		},
		Cache: DBBuilderCache{
			Archive: "./grype-db-cache.tar.gz",
		},
		Provider: DBBuilderProvider{
			Root: "./data",
			Vunnel: DBBuilderVunnel{
				Executor:    "docker",
				DockerImage: "ghcr.io/anchore/vunnel",
				DockerTag:   "latest",
				// rhel covers centos data within grype via namespace-distro remapping
				ExcludeProviders: []string{"centos"},
			},
		},
	}
}

func (o *DBBuilderConfig) PostLoad() error {
	// treat any configured env-var values as potentially sensitive
	for _, v := range o.Provider.Vunnel.Env {
		if v != "" {
			redact.Add(v)
		}
	}
	return nil
}

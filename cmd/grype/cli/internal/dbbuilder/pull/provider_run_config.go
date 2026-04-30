package pull

import (
	"github.com/anchore/grype/grype/db/provider"
)

// ProviderRunConfig is one entry in the db-builder pull provider list. The
// embedded Identifier supplies name + kind; Executor optionally overrides the
// global vunnel executor for this provider only (e.g. set "go" to drive a
// single provider through the in-process gonative registry while leaving the
// rest on docker-vunnel).
type ProviderRunConfig struct {
	provider.Identifier `yaml:",inline" mapstructure:",squash"`
	Executor            string `yaml:"executor,omitempty" json:"executor,omitempty" mapstructure:"executor"`
	Config              any    `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

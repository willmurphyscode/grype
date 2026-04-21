package pull

import (
	"github.com/anchore/grype/grype/db/provider"
)

type ProviderRunConfig struct {
	provider.Identifier `yaml:",inline" mapstructure:",squash"`
	Config              any `yaml:"config,omitempty" json:"config" mapstructure:"config"`
}

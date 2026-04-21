package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func DBBuilder(app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db-builder",
		Short: "developer tooling for building vulnerability databases from raw provider data",
		Long: `Developer tooling for building vulnerability databases from raw provider data.

These commands replace the separate grype-db binary for the "pull providers → build DB" loop,
so a developer extending or testing a vunnel provider can work from inside the grype repo
without a grype-db clone or Python/uv workspace.`,
	}

	cmd.AddCommand(
		DBBuilderPull(app),
		DBBuilderBuild(app),
		DBBuilderCache(app),
	)

	return cmd
}

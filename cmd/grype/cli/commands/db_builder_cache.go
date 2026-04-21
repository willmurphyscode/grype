package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
)

func DBBuilderCache(app clio.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "manage raw provider cache archives",
	}

	cmd.AddCommand(
		DBBuilderCacheRestore(app),
	)

	return cmd
}

package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func Main(version string, stdout, stderr io.Writer, args []string) error {
	versionFlag := "version"

	cmd := &cobra.Command{
		Use:           "a0daf",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			showVersion, err := cmd.Flags().GetBool(versionFlag)
			if err != nil {
				return err
			}

			if showVersion {
				fmt.Fprintln(stdout, version)
			}

			return nil
		},
	}

	cmd.Flags().Bool(versionFlag, false, "show version")

	cmd.SetArgs(args)

	return cmd.Execute()
}

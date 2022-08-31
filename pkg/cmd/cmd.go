package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/autopp/go-a0daf/pkg/auth"
	"github.com/spf13/cobra"
)

func Main(version string, stdout, stderr io.Writer, args []string) error {
	versionFlag := "version"
	baseURLEnv := "A0DAF_BASE_URL"
	clientIDEnv := "A0DAF_CLIENT_ID"
	scopeEnv := "A0DAF_SCOPE"
	audienceEnv := "A0DAF_AUDIENCE"

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

			undefinedEnvs := make([]string, 0)
			baseURL, ok := os.LookupEnv(baseURLEnv)
			if !ok {
				undefinedEnvs = append(undefinedEnvs, baseURLEnv)
			}
			clientID, ok := os.LookupEnv(clientIDEnv)
			if !ok {
				undefinedEnvs = append(undefinedEnvs, clientIDEnv)
			}
			scope, ok := os.LookupEnv(scopeEnv)
			if !ok {
				undefinedEnvs = append(undefinedEnvs, scopeEnv)
			}
			audience, ok := os.LookupEnv(audienceEnv)
			if !ok {
				undefinedEnvs = append(undefinedEnvs, audienceEnv)
			}
			if len(undefinedEnvs) != 0 {
				err := fmt.Errorf("undefined environment variables: %s", strings.Join(undefinedEnvs, ", "))
				fmt.Fprintln(stderr, err)
				return err
			}

			daf, err := auth.NewDeviceAuthFlow(auth.WithBaseURL(baseURL), auth.WithClientID(clientID))
			if err != nil {
				fmt.Fprintln(stderr, err)
				return err
			}

			dc, err := daf.FetchDeviceCode(scope, audience)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return err
			}

			fmt.Fprintf(stdout, "Access: %s\n", dc.VerificationURI)
			fmt.Fprintf(stdout, "Input: %s\n", dc.UserCode)

			token, err := daf.PollToken(dc)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return err
			}

			tokenJSON, err := json.Marshal(token)
			if err != nil {
				err = fmt.Errorf("cannot encode token response to json: %w", err)
				fmt.Fprintln(stderr, err)
				return err
			}

			fmt.Fprintln(stdout, string(tokenJSON))

			return nil
		},
	}

	cmd.Flags().Bool(versionFlag, false, "show version")

	cmd.SetArgs(args)

	return cmd.Execute()
}

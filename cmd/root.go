package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sfn-xml-sign",
	Short: "Signer and validator for XML files exchanged within Sistema Financeiro Nacional (SFN)",
	Long:  `Tool for signing and validating signatures of XML files exchanged within Sistema Financeiro Nacional (SFN).`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Use 'sfn-xml-sign --help' to show available commands.")
		os.Exit(2)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
}

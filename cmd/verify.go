package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
	"github.com/eduardoklosowski/sfn-xml-sign/xmldsign"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <type> <cert> [input]",
	Short: "Verify XML singature",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.RangeArgs(2, 3)(cmd, args); err != nil {
			return err
		}

		signType := args[0]
		if signType != "dict" && signType != "spi" {
			return fmt.Errorf("invalid signature type '%s'. Valid options: 'dict' and 'spi'", signType)
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		signType := args[0]

		cert, err := certificateutils.Load(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		var inputPath string
		if len(args) == 3 {
			inputPath = args[2]
		} else {
			inputPath = "-"
		}
		var input []byte
		if inputPath != "-" {
			input, err = os.ReadFile(inputPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		} else {
			var buffer bytes.Buffer
			_, err = io.Copy(&buffer, os.Stdin)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			input = buffer.Bytes()
		}

		switch signType {
		case "dict":
			err = xmldsign.Verify(cert, input)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		case "spi":
			err = xmldsign.VerifyIso20022(cert, input)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		println("Ok")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

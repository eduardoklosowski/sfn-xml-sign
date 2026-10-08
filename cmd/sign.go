package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/eduardoklosowski/sfn-xml-sign/internal/certificateutils"
	"github.com/eduardoklosowski/sfn-xml-sign/internal/keyutils"
	"github.com/eduardoklosowski/sfn-xml-sign/xmldsign"
)

var outputPath string

var signCmd = &cobra.Command{
	Use:   "sign <type> <cert> <key> [input]",
	Short: "Signs XML",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.RangeArgs(3, 4)(cmd, args); err != nil {
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

		key, err := keyutils.Load(args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		var inputPath string
		if len(args) == 4 {
			inputPath = args[3]
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

		var output *os.File
		if outputPath != "-" {
			output, err = os.Create(outputPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		} else {
			output = os.Stdout
		}

		var signedData []byte
		switch signType {
		case "dict":
			signedData, err = xmldsign.Sing(cert, key, input)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		case "spi":
			signedData, err = xmldsign.SingIso20022(cert, key, input)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		_, err = output.Write(signedData)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&outputPath, "output", "o", "-", "file to write signed XML")
}

package commands

import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"rsa-impl"
	"rsa-impl/private_key"
	"rsa-impl/public_key"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "rsa-impl",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var inputData []byte
		if inFilePath, err := cmd.Flags().GetString("in"); err != nil || inFilePath == "stdin" {
			inputData, _ = ioutil.ReadAll(os.Stdin)
		} else {
			if inputData, err = os.ReadFile(inFilePath); err != nil {
				return errors.Wrap(err, "invalid in path or file permissions")
			}
		}

		inKey, err := cmd.Flags().GetString("inkey")
		if err != nil {
			return errors.Wrap(err, "inkey required")
		}

		rawKey, err := os.ReadFile(inKey)
		if err != nil {
			return errors.Wrap(err, "invalid inkey path or file permissions")
		}

		isEncrypt, _ := cmd.Flags().GetBool("encrypt")
		isDecrypt, _ := cmd.Flags().GetBool("decrypt")

		var outData []byte
		switch {
		case isDecrypt:
			key, err := private_key.FromPEM(rawKey)
			if err != nil {
				return errors.Wrap(err, "invalid private key")
			}

			outData, err = rsa_impl.DecryptPKCS1v15(key, inputData)
			if err != nil {
				return errors.Wrap(err, "invalid inkey path or file permissions")
			}
		case isEncrypt:
			key, err := public_key.FromPEM(rawKey)
			if err != nil {
				return errors.Wrap(err, "invalid public key")
			}

			outData, err = rsa_impl.EncryptPKCS1v15(key, inputData)
			if err != nil {
				return errors.Wrap(err, "invalid inkey path or file permissions")
			}
		}

		if v, _ := cmd.Flags().GetBool("hexdump"); v {
			err := hexDump(outData)
			if err != nil {
				return err
			}
		} else {
			fmt.Printf("%s\n", outData)
		}
		return nil
	},
}

func hexDump(data []byte) error {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()

	_, err := stdoutDumper.Write(data)
	if err != nil {
		return err
	}

	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().Bool("encrypt", false, "encrypt with public key")
	rootCmd.Flags().Bool("decrypt", false, "decrypt with private key")

	rootCmd.Flags().String("in", "", "[file path|stdin] input file")
	rootCmd.Flags().String("out", "", "output file")
	rootCmd.Flags().String("inkey", "", "input key")
	rootCmd.Flags().String("keyformat", "PEM", "key format (currently support only PEM)")
	rootCmd.Flags().String("padding", "pkcs", "key padding (currently support only PKCS#1 v1.5)")

	rootCmd.Flags().Bool("hexdump", false, "output as hex table")
}

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/legit-labs/legit-attestation/pkg/legit_attest"
	"github.com/spf13/cobra"
)

var (
	keyPath      string
	key          string
	payloadPath  string
	payloadStdin bool
)

var rootCmd = &cobra.Command{
	Use:   "legit-attestation",
	Short: "simple in-toto attestation utility",
	RunE:  executeCmd,
}

func executeCmd(cmd *cobra.Command, _args []string) error {

	var payload []byte
	var err error
	if (!payloadStdin && payloadPath == "") || (payloadStdin && payloadPath != "") {
		return fmt.Errorf("please provide either a payload or set -payload-stdin to read it from stdin")
	} else if payloadStdin {
		if payload, err = ioutil.ReadAll(os.Stdin); err != nil {
			return fmt.Errorf("failed to read payload from stdin: %v", err)
		}
	} else {
		payload, err = os.ReadFile(payloadPath)
		if err != nil {
			return fmt.Errorf("failed to open payload at %v: %v", payloadPath, err)
		}
	}

	cleaner := func() {}
	if (key != "" && keyPath != "") || (key == "" && keyPath == "") {
		return fmt.Errorf("please provide either key or key-path")
	} else if key != "" {
		keyPath, cleaner, err = legit_attest.KeyPathFromKey([]byte(key))
		if err != nil {
			return fmt.Errorf("failed to make a path from the input key: %v", err)
		}
		key = ""
	}
	defer cleaner()

	attestation, err := legit_attest.Attest(context.Background(), keyPath, payload)
	if err != nil {
		return fmt.Errorf("failed to attest: %v", err)
	}

	// Print the attestation as json output to stdout
	fmt.Printf("%v", string(attestation))

	return nil
}

func main() {
	flag := rootCmd.Flags()

	flag.StringVar(&keyPath, "key-path", "", "The path of the private key")
	flag.StringVar(&key, "key", "", "The private key")
	flag.StringVar(&payloadPath, "payload-path", "", "The path to a file containing payload to attest")
	flag.BoolVar(&payloadStdin, "payload-stdin", false, "Read the json from stdin (overwrites -payload-path if provided)")

	if err := rootCmd.Execute(); err != nil {
		log.Panicf("execution falure: %v", err)
	}
}

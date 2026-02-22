package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/therelicai/therelic/internal/cli"
)

const version = "v0.1.0-dev"

func main() {
	fmt.Fprintf(os.Stderr, "relic %s\n", version)

	root := cli.NewRootCmd(version)
	if err := root.Execute(); err != nil {
		// Propagate the child process exit code transparently.
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

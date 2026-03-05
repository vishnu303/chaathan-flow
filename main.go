package main

import (
	"fmt"
	"os"

	"github.com/vishnu303/chaathan-flow/cli"
	"github.com/vishnu303/chaathan-flow/pkg/database"
)

func main() {
	// Ensure database is properly closed on exit (flushes WAL, releases locks)
	defer database.Close()

	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

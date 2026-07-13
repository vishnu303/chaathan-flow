package main

import (
	"fmt"
	"os"

	"github.com/vishnu303/chaathan/cli"
	"github.com/vishnu303/chaathan/pkg/database"
	"github.com/vishnu303/chaathan/pkg/paths"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run encapsulates the main execution flow to guarantee deferred closures
// (like closing the SQLite database handle) are executed before the process exits.
func run() error {
	// Resolve ~/.chaathan home directory once at startup
	if err := paths.Init(); err != nil {
		return err
	}

	// Ensure database is properly closed on exit (flushes WAL, releases locks)
	defer func() {
		if err := database.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close database: %v\n", err)
		}
	}()

	return cli.Execute()
}

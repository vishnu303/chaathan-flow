// Package paths provides centralised resolution of the Chaathan home directory
// and common sub-paths. It resolves os.UserHomeDir exactly once and fails
// loudly so that callers never silently operate on "/" or an empty path.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// chaathanHome is resolved once at startup via Init or lazily on first use.
var (
	chaathanHome string
	initOnce     sync.Once
	initErr      error
)

// Init resolves the Chaathan home directory. It checks the CHAATHAN_HOME
// environment variable first; if empty or unset, it defaults to ~/.chaathan.
// It must be called early in main() or a PersistentPreRun. Subsequent calls are no-ops.
// Returns an error if the home directory cannot be determined.
func Init() error {
	initOnce.Do(func() {
		if envHome := os.Getenv("CHAATHAN_HOME"); envHome != "" {
			chaathanHome = filepath.Clean(envHome)
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				initErr = fmt.Errorf("cannot determine home directory: %w", err)
				return
			}
			chaathanHome = filepath.Join(home, ".chaathan")
		}

		// Guarantee home directory exists
		if err := os.MkdirAll(chaathanHome, 0755); err != nil {
			initErr = fmt.Errorf("cannot create home directory: %w", err)
		}
	})
	return initErr
}

// ChaathanHome returns the resolved ~/.chaathan directory.
// Panics if Init() was never called or failed — this is intentional because
// all callers previously used `home, _ := os.UserHomeDir()` which silently
// produced broken paths.
func ChaathanHome() string {
	if chaathanHome == "" {
		// Attempt lazy init for callers that didn't go through Init()
		if err := Init(); err != nil {
			panic("paths.ChaathanHome called before successful Init(): " + err.Error())
		}
	}
	return chaathanHome
}

// StateDir returns the scan state directory (~/.chaathan/state). The caller must ensure this directory exists using os.MkdirAll.
func StateDir() string {
	return filepath.Join(ChaathanHome(), "state")
}

// ScansDir returns the default scans output directory (~/.chaathan/scans). The caller must ensure this directory exists using os.MkdirAll.
func ScansDir() string {
	return filepath.Join(ChaathanHome(), "scans")
}

// ReportsDir returns the reports directory (~/.chaathan/reports). The caller must ensure this directory exists using os.MkdirAll.
func ReportsDir() string {
	return filepath.Join(ChaathanHome(), "reports")
}

// DatabasePath returns the default database path (~/.chaathan/chaathan.db).
func DatabasePath() string {
	return filepath.Join(ChaathanHome(), "chaathan.db")
}

// ConfigPath returns the default config file path (~/.chaathan/config.yaml).
func ConfigPath() string {
	return filepath.Join(ChaathanHome(), "config.yaml")
}

// LogsDir returns the scan log directory (~/.chaathan/logs). The caller must ensure this directory exists using os.MkdirAll.
func LogsDir() string {
	return filepath.Join(ChaathanHome(), "logs")
}

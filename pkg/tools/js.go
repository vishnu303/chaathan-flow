package tools

import (
	"context"
	"strings"

	"github.com/vishnu303/chaathan/pkg/runner"
	"github.com/vishnu303/chaathan/utils"
)

// RunJsluiceURLs extracts URLs and API routes from a local JavaScript file
// using jsluice's AST-based analysis. Output is JSON lines written to outputFile.
func (t *ToolBox) RunJsluiceURLs(ctx context.Context, jsFile string, outputFile string) error {
	args := []string{"urls", jsFile}
	output, err := t.Runner.Run(ctx, ToolJsluice, args, runner.WithNoRetry())
	// Keep only JSON object lines — jsluice may print warnings to stdout.
	output = utils.FilterOutputLines(output, func(line string) bool {
		return strings.HasPrefix(strings.TrimSpace(line), "{")
	})
	if output != "" {
		if writeErr := utils.WriteToFile(outputFile, output); writeErr != nil {
			return writeErr
		}
	}
	return err
}

// RunX8WithWordlist discovers hidden HTTP parameters using x8 and the given wordlist.

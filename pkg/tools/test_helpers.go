package tools

import (
	"context"
	"fmt"

	"github.com/vishnu303/chaathan/utils"
)

// RunFfufArgsTestHelper exports buildFfufArgs for testing.
func (t *ToolBox) RunFfufArgsTestHelper(url string, wordlist string, outputFile string) []string {
	return t.buildFfufArgs(url, wordlist, outputFile)
}

// AppendCommonTestHelper exports appendCommon for testing.
func (t *ToolBox) AppendCommonTestHelper(args []string, uaHeader bool, tlsOpSec bool, customHFlag string, cookieFlag string, proxyFlag string) []string {
	return t.appendCommon(args, appendOptions{
		uaHeader:    uaHeader,
		tlsOpSec:    tlsOpSec,
		customHFlag: customHFlag,
		cookieFlag:  cookieFlag,
		proxyFlag:   proxyFlag,
	})
}

// WriteToFileTestHelper exports writeToFile for testing.
func (t *ToolBox) WriteToFileTestHelper(path string, content string) error {
	return utils.WriteToFile(path, content)
}

// RunFfuf is a test-only convenience wrapper around buildFfufArgs + Runner.Run.
func (t *ToolBox) RunFfuf(ctx context.Context, url string, wordlist string, outputFile string) error {
	if wordlist == "" {
		return fmt.Errorf("ffuf requires a wordlist path")
	}
	args := t.buildFfufArgs(url, wordlist, outputFile)
	_, err := t.Runner.Run(ctx, ToolFfuf, args)
	return err
}

// RunX8 is a test-only convenience wrapper around RunX8WithWordlist.
func (t *ToolBox) RunX8(ctx context.Context, inputFile string, outputFile string) error {
	return t.RunX8WithWordlist(ctx, inputFile, outputFile, "")
}

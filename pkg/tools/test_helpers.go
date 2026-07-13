package tools

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
	return writeToFile(path, content)
}

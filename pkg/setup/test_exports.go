package setup

import "io"

var GoArchSuffix = goArchSuffix
var ParseGoVersion = parseGoVersion
var VerifySHA256 = verifySHA256
var PathListContains = pathListContains
var ContainsWord = containsWord
var AppendLinesToFile = appendLinesToFile
var IsValidPythonModule = isValidPythonModule
var Sublist3rPinArgs = &sublist3rPinArgs

// Export verifySHA256 as a function for tests
func VerifySHA256Func(r io.Reader, expectedHex string) error {
	return verifySHA256(r, expectedHex)
}

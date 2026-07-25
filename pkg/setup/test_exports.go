package setup

import "io"

var GoArchSuffix = goArchSuffix
var ParseGoVersion = parseGoVersion
var PathListContains = pathListContains
var ContainsWord = containsWord
var AppendLinesToFile = appendLinesToFile
var IsValidPythonModule = isValidPythonModule
var Sublist3rPinArgs = &sublist3rPinArgs
var ResolveGOPATH = resolveGOPATH

// VerifySHA256Func exports verifySHA256 for tests.
func VerifySHA256Func(r io.Reader, expectedHex string) error {
	return verifySHA256(r, expectedHex)
}

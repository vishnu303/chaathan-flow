package wildcard_flow

// Exported variables and methods for testing purposes only
var PathKey = pathKey
var URLROIScore = urlROIScore
var ConvertX8ToURLs = convertX8ToURLs
var FilterAndDeduplicateHosts = filterAndDeduplicateHosts
var ShannonEntropy = shannonEntropy
var IsLikelySecret = isLikelySecret
var ExtractContext = extractContext

type X8Result = x8Result
type X8FoundParameter = x8FoundParameter

func (c *Ctx) ResumeOrSkip(stepName, stepHeader string) (bool, bool) {
	return c.resumeOrSkip(stepName, stepHeader)
}

func (c *Ctx) MarkStepFailedSafe(stepName string, stepErr error) {
	c.markStepFailedSafe(stepName, stepErr)
}

func (c *Ctx) MarkStepCompleteSafe(stepName string) {
	c.markStepCompleteSafe(stepName)
}

func (c *Ctx) MarkStepCompleteIfNoFailure(stepName string) {
	c.markStepCompleteIfNoFailure(stepName)
}

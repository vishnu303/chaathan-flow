package wildcard_flow

// Exported variables and methods for testing purposes only
var PathKey = pathKey
var URLROIScore = urlROIScore
var ConvertX8ToURLs = convertX8ToURLs
var ShannonEntropy = shannonEntropy
var IsLikelySecret = isLikelySecret
var ExtractSecretContext = extractSecretContext
var RankJSURLs = rankJSURLs
var ExtractSubdomainsFromJS = extractSubdomainsFromJS
var NucleiMaxTimeout = nucleiMaxTimeout
var DalfoxMaxTimeout = dalfoxMaxTimeout

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

func (c *Ctx) FilterSubsToScope(filePath string) {
	c.filterSubsToScope(filePath)
}

func StepTakeoverDetection(c *Ctx) bool {
	return stepTakeoverDetection(c).Cancelled
}

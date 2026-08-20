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
var CollectLiveHostTargetsFromHttpx = collectLiveHostTargetsFromHttpx
var DedupeHostURLsFile = dedupeHostURLsFile
var CollectX8Targets = collectX8Targets
var IsHighSignalURL = isHighSignalURL
var GatherJSURLs = gatherJSURLs
var WriteJSOutputFiles = writeJSOutputFiles
var ValidateJWT = validateJWT
var ValidateAWSKey = validateAWSKey
var ValidateSlackWebhook = validateSlackWebhook
var ValidateGoogleAPIKey = validateGoogleAPIKey
var ExtractAWSSecretFromContext = extractAWSSecretFromContext
var AWSErrorCode = awsErrorCode
var SourceMapCandidates = sourceMapCandidates

type X8Result = x8Result
type X8FoundParameter = x8FoundParameter
type SecretFinding = secretFinding

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

func (c *Ctx) HostInScope(host string) bool {
	return c.hostInScope(host)
}

func StepTakeoverDetection(c *Ctx) bool {
	return stepTakeoverDetection(c).Cancelled
}

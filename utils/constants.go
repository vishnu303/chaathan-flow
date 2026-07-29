package utils

import "slices"

// junkDomains are 3rd-party domains that should never be scanned.
var junkDomains = []string{
	"googleapis.com",
	"gstatic.com",
	"google-analytics.com",
	"googletagmanager.com",
	"doubleclick.net",
	"googlesyndication.com",
	"facebook.com",
	"fbcdn.net",
	"twitter.com",
	"twimg.com",
	"cloudflare.com",
	"cdnjs.cloudflare.com",
	"cdn.jsdelivr.net",
	"unpkg.com",
	"maxcdn.bootstrapcdn.com",
	"bootstrapcdn.com",
	"jquery.com",
	"fontawesome.com",
	"fonts.googleapis.com",
	"gravatar.com",
	"wp.com",
	"amazon-adsystem.com",
	"hotjar.com",
	"clarity.ms",
	"segment.io",
	"segment.com",
	"intercom.io",
	"sentry.io",
	"newrelic.com",
	"nr-data.net",
	"akamaihd.net",
	"akamai.net",
	"fastly.net",
	"edgecastcdn.net",
	"cloudfront.net",
	"azureedge.net",
	"azurewebsites.net",
	"herokuapp.com",
	"github.io",
	"gitlab.io",
	"recaptcha.net",
	"hcaptcha.com",
}

// staticExtensions are file extensions that cannot have injection points.
var staticExtensions = []string{
	".js",
	".css",
	".png",
	".jpg",
	".jpeg",
	".gif",
	".svg",
	".ico",
	".woff",
	".woff2",
	".ttf",
	".eot",
	".otf",
	".mp4",
	".webm",
	".mp3",
	".pdf",
	".zip",
	".gz",
	".tar",
	".map",
	".webp",
	".avif",
	".bmp",
	".tif",
}

// highValueMarkers are path markers identifying high-value/sensitive components.
var highValueMarkers = []string{
	"/admin",
	"/login",
	"/signin",
	"/signup",
	"/auth",
	"/oauth",
	"/token",
	"/graphql",
	"/api",
	"/v1/",
	"/v2/",
	"/rest/",
	"/debug",
	"/console",
	"/actuator",
	"/swagger",
	"/openapi",
	"/health",
	"/metrics",
	"/config",
	"/upload",
	"/callback",
	"/redirect",
	"/reset",
	"/password",
	"/search",
	"/export",
	"/import",
	"/webhook",
}

// interestingParameters are parameter names that often contain security vulnerabilities.
var interestingParameters = []string{
	"url",
	"uri",
	"path",
	"redirect",
	"return",
	"next",
	"goto",
	"file",
	"page",
	"template",
	"include",
	"cmd",
	"exec",
	"query",
	"search",
	"id",
	"user",
	"email",
	"callback",
}

// interestingEndpointsPatterns are path substrings used to identify high-value or sensitive API endpoints.
var interestingEndpointsPatterns = []string{
	"/api/", "/v1/", "/v2/", "/v3/",
	"/admin", "/login", "/auth",
	"/graphql", "/rest/",
	"/upload", "/download",
	"/config", "/settings",
	"/debug", "/test",
	".json", ".xml",
	"/swagger", "/docs",
}

// JunkDomains returns a copy of the 3rd-party junk domain list (callers may not mutate the source).
func JunkDomains() []string { return slices.Clone(junkDomains) }

// StaticExtensions returns a copy of the static file extension list.
func StaticExtensions() []string { return slices.Clone(staticExtensions) }

// HighValueMarkers returns a copy of the high-value path marker list.
func HighValueMarkers() []string { return slices.Clone(highValueMarkers) }

// InterestingParameters returns a copy of the interesting parameter name list.
func InterestingParameters() []string { return slices.Clone(interestingParameters) }

// InterestingEndpointsPatterns returns a copy of the interesting endpoint pattern list.
func InterestingEndpointsPatterns() []string { return slices.Clone(interestingEndpointsPatterns) }

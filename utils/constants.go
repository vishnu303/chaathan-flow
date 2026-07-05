package utils

// JunkDomains are 3rd-party domains that should never be scanned.
// This slice is read-only; do not mutate.
var JunkDomains = []string{
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

// StaticExtensions are file extensions that cannot have injection points.
// This slice is read-only; do not mutate.
var StaticExtensions = []string{
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

// HighValueMarkers are path markers identifying high-value/sensitive components.
// This slice is read-only; do not mutate.
var HighValueMarkers = []string{
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

// InterestingParameters are parameter names that often contain security vulnerabilities.
// This slice is read-only; do not mutate.
var InterestingParameters = []string{
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

// InterestingEndpointsPatterns are path substrings used to identify high-value or sensitive API endpoints.
// This slice is read-only; do not mutate.
var InterestingEndpointsPatterns = []string{
	"/api/", "/v1/", "/v2/", "/v3/",
	"/admin", "/login", "/auth",
	"/graphql", "/rest/",
	"/upload", "/download",
	"/config", "/settings",
	"/debug", "/test",
	".json", ".xml",
	"/swagger", "/docs",
}

// JunkDomainsSet returns a read-only set (map) of JunkDomains for O(1) lookup.
func JunkDomainsSet() map[string]bool {
	set := make(map[string]bool, len(JunkDomains))
	for _, domain := range JunkDomains {
		set[domain] = true
	}
	return set
}


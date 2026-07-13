package proxy_scraping

import "context"

var HTTPSources = &httpSources
var Socks4Sources = &socks4Sources
var Socks5Sources = &socks5Sources

func FetchProxySources(ctx context.Context, proxyTypes []string, outPath string) (int, error) {
	return fetchProxySources(ctx, proxyTypes, outPath)
}

package metadata

import (
	"context"
	"net/http"
)

type HTTPSignal = httpSignal

// FetchSignal is a test-only export that delegates to fetchSignal so tests
// can exercise the collector's HTTP parsing logic directly. The ctx is
// threaded through to the underlying request so tests using a cancellable
// context behave identically to production callers.
func FetchSignal(ctx context.Context, client *http.Client, rawURL string) (HTTPSignal, bool) {
	return fetchSignal(ctx, client, rawURL)
}

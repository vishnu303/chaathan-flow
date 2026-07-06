package metadata

import "net/http"

type HTTPSignal = httpSignal

func FetchSignal(client *http.Client, rawURL string) (HTTPSignal, bool) {
	return fetchSignal(client, rawURL)
}

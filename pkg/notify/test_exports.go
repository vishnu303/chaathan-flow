package notify

import "net/http"

func (n *Notifier) SetClient(client *http.Client) {
	n.client = client
}

func (n *Notifier) PostJSON(url string, payload any) error {
	return n.postJSON(url, payload)
}

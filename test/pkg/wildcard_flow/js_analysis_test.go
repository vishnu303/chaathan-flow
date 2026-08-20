package wildcard_flow_test

import (
	"testing"

	"github.com/vishnu303/chaathan/pkg/wildcard_flow"
)

func TestSourceMapCandidates(t *testing.T) {
	tests := []struct {
		name string
		js   string
		body string
		want []string
	}{
		{
			name: "directive equal to .map fallback dedupes",
			js:   "https://example.com/static/app.js",
			body: "// code\n//# sourceMappingURL=app.js.map\n",
			want: []string{"https://example.com/static/app.js.map"},
		},
		{
			name: "relative directive resolved against js url",
			js:   "https://example.com/static/app.js",
			body: "//# sourceMappingURL=../maps/app.map\n",
			want: []string{
				"https://example.com/maps/app.map",
				"https://example.com/static/app.js.map",
			},
		},
		{
			name: "absolute directive url kept alongside fallback",
			js:   "https://example.com/app.js",
			body: "//# sourceMappingURL=https://cdn.example.com/app.js.map\n",
			want: []string{
				"https://cdn.example.com/app.js.map",
				"https://example.com/app.js.map",
			},
		},
		{
			name: "legacy @# directive honored",
			js:   "https://example.com/legacy.js",
			body: "//@ sourceMappingURL=legacy.map\n",
			want: []string{
				"https://example.com/legacy.map",
			},
		},
		{
			name: "data uri skipped, fallback only",
			js:   "https://example.com/inline.js",
			body: "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n",
			want: []string{"https://example.com/inline.js.map"},
		},
		{
			name: "no body means fallback only",
			js:   "https://example.com/plain.js",
			body: "",
			want: []string{"https://example.com/plain.js.map"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := wildcard_flow.SourceMapCandidates(tc.js, []byte(tc.body))
			if len(got) != len(tc.want) {
				t.Fatalf("SourceMapCandidates(%q) = %v; want %v", tc.js, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("candidate[%d] = %q; want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

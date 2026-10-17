package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthCheck(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		good       bool
	}{
		{"ready", `{"ok":true}`, 200, true},
		{"not-ready", `{"ok":false}`, 200, false},
		{"invalid", "not JSON", 200, false},
		{"error", `{"ok":true}`, 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer server.Close()
			if err := healthCheck(server.URL); (err == nil) != tc.good {
				t.Fatalf("health result: %v", err)
			}
		})
	}
}

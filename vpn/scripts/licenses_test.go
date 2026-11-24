//go:build vpnlicenses

package main

import "testing"

func TestHTTPURLCanonicalizesGVisorRepository(t *testing.T) {
	const canonical = "https://github.com/gvisor/gvisor/blob/a6f909f08a72/LICENSE"
	tests := map[string]string{
		"https://github.com/google/gvisor/blob/a6f909f08a72/LICENSE": canonical,
		"https://github.com/gvisor/gvisor/blob/a6f909f08a72/LICENSE": canonical,
		"https://github.com/google/gvisor":                           "https://github.com/gvisor/gvisor",
		"https://github.com/google/gvisor-example/LICENSE":           "https://github.com/google/gvisor-example/LICENSE",
	}
	for input, want := range tests {
		if got := httpURL(input); got != want {
			t.Errorf("httpURL(%q) = %q, want %q", input, got, want)
		}
	}
}

package enroll

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPerIPRejectReturnsTheGlobalToken(t *testing.T) {
	cfg := Config{
		ControlURL:          "https://vpn.example.org",
		GlobalRatePerMinute: 2,
		PerIPRatePerMinute:  1,
		Tenants: []Tenant{{
			Name:            "acme",
			HeadscaleUserID: "1",
			TokenHashes:     []string{HashToken("seed")},
		}},
	}
	s, err := NewServer(cfg, &fakeMinter{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	hit := func(ip string) bool {
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll", nil)
		req.RemoteAddr = ip + ":9"
		_, ok := s.admit(httptest.NewRecorder(), req)
		return ok
	}
	if !hit("203.0.113.9") {
		t.Fatal("first request from an address should pass")
	}
	if hit("203.0.113.9") {
		t.Fatal("second request from the same address should be limited")
	}
	if !hit("203.0.113.10") {
		t.Fatal("another address should still pass after a per-IP reject")
	}
	if hit("203.0.113.11") {
		t.Fatal("global budget is 2 and both admits were spent")
	}
}

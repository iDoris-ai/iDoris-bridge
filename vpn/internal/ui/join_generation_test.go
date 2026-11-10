package ui

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/gateway"
	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

func TestHandleJoinDropsPlanFromThePreviousCode(t *testing.T) {
	code, err := join.Encode(join.Payload{
		V:            join.Version,
		EnrollURL:    "https://new.example/enroll",
		Token:        "new-token",
		Role:         join.RoleMember,
		Tenant:       "acme",
		HostnameHint: "host",
	}, join.Options{})
	if err != nil {
		t.Fatal(err)
	}
	applied := false
	s := &Server{svc: Services{
		Home: func() (string, error) { return t.TempDir(), nil },
		Apply: func(gateway.Plan, gateway.ApplyOptions) (gateway.ApplyResult, error) {
			applied = true
			return gateway.ApplyResult{}, nil
		},
	}}
	s.join = &heldJoin{EnrollURL: "https://old.example/enroll", Token: "old-token", Tenant: "old", Hostname: "host"}
	s.plan = &gateway.Plan{EnrollURL: "https://old.example/enroll"}
	s.joinGen = 1
	s.planGen = 1

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/join", strings.NewReader(`{"code":`+strconv.Quote(code)+`}`))
	s.handleJoin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("join: %d %s", rec.Code, rec.Body.String())
	}
	if s.plan != nil {
		t.Fatal("old plan still set after a new join code")
	}
	if s.join == nil || s.join.Token != "new-token" || s.join.EnrollURL != "https://new.example/enroll" {
		t.Fatalf("join: %+v", s.join)
	}

	rec = httptest.NewRecorder()
	s.handleApply(rec, httptest.NewRequest(http.MethodPost, "/api/apply", nil))
	if applied {
		t.Fatal("apply ran without a plan for the new code")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHandleApplyRefusesPlanFromAnotherJoin(t *testing.T) {
	var gotToken, gotURL string
	s := &Server{svc: Services{
		Apply: func(plan gateway.Plan, opt gateway.ApplyOptions) (gateway.ApplyResult, error) {
			gotToken = opt.Token
			gotURL = plan.EnrollURL
			return gateway.ApplyResult{}, nil
		},
	}}
	s.join = &heldJoin{Token: "new-token", EnrollURL: "https://new.example/enroll"}
	s.plan = &gateway.Plan{EnrollURL: "https://old.example/enroll"}
	s.joinGen = 2
	s.planGen = 1

	rec := httptest.NewRecorder()
	s.handleApply(rec, httptest.NewRequest(http.MethodPost, "/api/apply", nil))
	if rec.Code != http.StatusBadRequest || gotToken != "" {
		t.Fatalf("stale plan: code %d token %q body %s", rec.Code, gotToken, rec.Body.String())
	}

	s.planGen = 2
	s.plan.EnrollURL = "https://new.example/enroll"
	rec = httptest.NewRecorder()
	s.handleApply(rec, httptest.NewRequest(http.MethodPost, "/api/apply", nil))
	if rec.Code != http.StatusOK || gotToken != "new-token" || gotURL != "https://new.example/enroll" {
		t.Fatalf("matching plan: code %d token %q url %s body %s", rec.Code, gotToken, gotURL, rec.Body.String())
	}
}

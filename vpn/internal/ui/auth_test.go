package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLaunchSecretOverridesStaleCookie(t *testing.T) {
	s := &Server{secret: "new-secret"}
	req := httptest.NewRequest(http.MethodGet, "/?k=new-secret", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "old-secret"})
	if !s.authorized(req) {
		t.Fatal("valid launch secret was rejected because of a stale cookie")
	}

	stale := httptest.NewRequest(http.MethodGet, "/", nil)
	stale.AddCookie(&http.Cookie{Name: cookieName, Value: "old-secret"})
	if s.authorized(stale) {
		t.Fatal("stale cookie alone should fail")
	}

	both := httptest.NewRequest(http.MethodGet, "/", nil)
	both.AddCookie(&http.Cookie{Name: cookieName, Value: "new-secret"})
	both.Header.Set(secretHeader, "wrong")
	if s.authorized(both) {
		t.Fatal("a mismatched header should still fail when there is no launch secret")
	}

	wrongK := httptest.NewRequest(http.MethodGet, "/?k=old-secret", nil)
	wrongK.AddCookie(&http.Cookie{Name: cookieName, Value: "new-secret"})
	if s.authorized(wrongK) {
		t.Fatal("a wrong launch secret should still fail")
	}
}

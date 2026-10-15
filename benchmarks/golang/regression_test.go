package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminAccessControlRegression(t *testing.T) {
	patched := &PatchedServer{}

	// Request without authorization must be 403 Forbidden
	reqUnauth := httptest.NewRequest("GET", "/admin/stats", nil)
	rrUnauth := httptest.NewRecorder()
	patched.AdminStatsHandler(rrUnauth, reqUnauth)

	if status := rrUnauth.Code; status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for unauthorized request, got %v", status)
	}

	// Request with valid authorization must succeed (200 OK)
	reqAuth := httptest.NewRequest("GET", "/admin/stats", nil)
	reqAuth.Header.Set("Authorization", "Bearer secret-admin-key")
	rrAuth := httptest.NewRecorder()
	patched.AdminStatsHandler(rrAuth, reqAuth)

	if status := rrAuth.Code; status != http.StatusOK {
		t.Errorf("Expected 200 OK for authorized request, got %v", status)
	}

	if !strings.Contains(rrAuth.Body.String(), `"admin_access":true`) {
		t.Errorf("Expected response body to contain admin_access, got %v", rrAuth.Body.String())
	}
}

func TestSSRFMitigation(t *testing.T) {
	patched := &PatchedServer{}

	// Malicious loopback SSRF attempt
	req := httptest.NewRequest("GET", "/fetch?url=http://127.0.0.1:8080/internal-secrets", nil)
	rr := httptest.NewRecorder()
	patched.FetchURLHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for loopback SSRF, got %v", status)
	}
}

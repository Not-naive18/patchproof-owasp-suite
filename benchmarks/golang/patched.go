package main

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// PatchedServer holds secure, verified endpoints
type PatchedServer struct {
	DB *sql.DB
}

// PATCH A01: Broken Access Control Remediated with Token Authorization
func (s *PatchedServer) AdminStatsHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "Bearer secret-admin-key" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","system_load":0.12,"admin_access":true}`))
}

// PATCH A03: Parameterized SQL Query
func (s *PatchedServer) SearchUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// SECURE: Parameterized placeholder prevents SQL injection
	query := "SELECT id, username FROM users WHERE username = ?"
	rows, err := s.DB.Query(query, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"status":"success","matches":%d}`, count)))
}

// Safe SSRF validator
func isSafeURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	hostname := u.Hostname()
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

// PATCH A10: SSRF Defense
func (s *PatchedServer) FetchURLHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if !isSafeURL(target) {
		http.Error(w, `{"error":"forbidden target address"}`, http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body)
}

package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
)

// VulnerableServer holds unauthenticated or vulnerable endpoints
type VulnerableServer struct {
	DB *sql.DB
}

// OWASP A01:2021 - Broken Access Control: Unchecked Admin Handler
func (s *VulnerableServer) AdminStatsHandler(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: No role check or token verification
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success","system_load":0.12,"admin_access":true}`))
}

// OWASP A03:2021 - Injection: SQL Injection via fmt.Sprintf
func (s *VulnerableServer) SearchUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// VULNERABLE: Direct string formatting into SQL query
	query := fmt.Sprintf("SELECT id, username FROM users WHERE username = '%s'", username)
	rows, err := s.DB.Query(query)
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

// OWASP A10:2021 - Server-Side Request Forgery (SSRF)
func (s *VulnerableServer) FetchURLHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// VULNERABLE: Blindly requesting external or internal address
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body)
}

package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthentication(t *testing.T) {
	var hashed bytes.Buffer
	password := strings.Repeat("ж", 100) + ":%long-password"
	plain, _ := json.Marshal(map[string]string{"alice": password})
	if err := run([]string{"hash"}, bytes.NewReader(plain), &hashed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hashed.String(), password) {
		t.Fatal("Plaintext password leaked into output")
	}
	users, err := loadUsers(&hashed)
	if err != nil {
		t.Fatal(err)
	}
	handler := authHandler(users)
	for _, test := range []struct {
		name, method, path, body string
		status                   int
		ok                       bool
	}{
		{"correct", "POST", "/auth", "", 200, true},
		{"wrong", "POST", "/auth", `{"username":"alice","password":"wrong"}`, 200, false},
		{"unknown", "POST", "/auth", `{"username":"nobody","password":"wrong"}`, 200, false},
		{"empty", "POST", "/auth", `{"username":"alice","password":""}`, 400, false},
		{"malformed", "POST", "/auth", `{`, 400, false},
		{"trailing", "POST", "/auth", `{} {}`, 400, false},
		{"oversized", "POST", "/auth", strings.Repeat("x", maxBody+1), 400, false},
		{"get", "GET", "/auth", "", 405, false},
		{"other", "POST", "/other", "{}", 404, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := test.body
			if test.name == "correct" {
				data, _ := json.Marshal(map[string]any{"username": "alice", "password": password, "service": "test", "client": "127.0.0.1"})
				body = string(data)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(test.method, test.path, strings.NewReader(body)))
			if w.Code != test.status {
				t.Fatalf("Status %d, expected %d", w.Code, test.status)
			}
			if w.Code == 200 {
				var result struct {
					OK bool   `json:"ok"`
					ID string `json:"id"`
				}
				if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.OK != test.ok || (test.ok && result.ID != "alice") || (!test.ok && result.ID != "") {
					t.Fatal("Unexpected authentication response")
				}
			}
			if strings.Contains(w.Body.String(), password) {
				t.Fatal("Password leaked into response")
			}
		})
	}
	for _, input := range []string{`{}`, `null`, `{"alice":"plaintext"}`, `{"alice":"$pbkdf2-sha256$1$00$00"}`, `{"alice":null}`} {
		if _, err := loadUsers(strings.NewReader(input)); err == nil {
			t.Fatalf("Accepted invalid users file: %s", input)
		}
	}
	for _, address := range []string{"0.0.0.0:18081", "localhost:18081", ":18081", "192.0.2.1:80"} {
		if loopbackAddress(address) {
			t.Fatalf("Accepted non-loopback address: %s", address)
		}
	}
	if !loopbackAddress("127.0.0.1:18081") || !loopbackAddress("[::1]:18081") {
		t.Fatal("Rejected loopback address")
	}
}

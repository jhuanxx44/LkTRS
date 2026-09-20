package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *app {
	t.Helper()
	a, err := newApp(config{root: t.TempDir()}, "127.0.0.1:8787")
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func request(a *app, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+a.host+path, strings.NewReader(body))
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Demo-Token", a.token)
	}
	for key, value := range headers {
		if key == "Host" {
			r.Host = value
		} else {
			r.Header.Set(key, value)
		}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func TestHTTPBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		headers                  map[string]string
		status                   int
	}{
		{"foreign host", "GET", "/api/state", "", map[string]string{"Host": "attacker.example"}, 403},
		{"foreign origin", "GET", "/api/state", "", map[string]string{"Origin": "https://attacker.example"}, 403},
		{"cross site", "GET", "/api/state", "", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"no token", "POST", "/api/advance", `{"step":0}`, map[string]string{"X-Demo-Token": ""}, 403},
		{"wrong token", "POST", "/api/reset", `{}`, map[string]string{"X-Demo-Token": "bad"}, 403},
		{"form post", "POST", "/api/advance", `{"step":0}`, map[string]string{"Content-Type": "text/plain"}, 415},
		{"unknown field", "POST", "/api/advance", `{"step":0,"extra":1}`, nil, 400},
		{"duplicate field", "POST", "/api/advance", `{"step":1,"step":2}`, nil, 400},
		{"trailing body", "POST", "/api/advance", `{"step":0} {}`, nil, 400},
		{"oversized body", "POST", "/api/advance", strings.Repeat(" ", 1025) + `{"step":0}`, nil, 400},
		{"missing step", "POST", "/api/advance", `{}`, nil, 409},
		{"null step", "POST", "/api/advance", `{"step":null}`, nil, 409},
		{"out of order", "POST", "/api/advance", `{"step":3}`, nil, 409},
		{"reset args", "POST", "/api/reset", `{"step":0}`, nil, 400},
		{"missing export", "GET", "/api/export", "", nil, 409},
		{"path traversal", "GET", "/../engine.go", "", nil, 404},
		{"unexpected method", "PUT", "/api/state", "", nil, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp(t)
			w := request(a, tc.method, tc.path, tc.body, tc.headers)
			if w.Code != tc.status {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if a.state.Busy || a.state.Next != 0 {
				t.Fatal("rejected request changed workflow")
			}
		})
	}
}
func TestWorkflowGuardsAndPublicRoutes(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/state"} {
		w := request(a, "GET", path, "", nil)
		if w.Code != 200 || w.Body.Len() == 0 || w.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("bad route %s: %d", path, w.Code)
		}
	}
	w := request(a, "GET", "/api/state", "", nil)
	var state view
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil || len(state.Steps) != 8 || len(state.Token) != 64 {
		t.Fatal("bad initial state", err)
	}
	a.state.Busy = true
	for _, path := range []string{"/api/reset", "/api/advance"} {
		body := `{}`
		if path == "/api/advance" {
			body = `{"step":0}`
		}
		if w := request(a, "POST", path, body, nil); w.Code != 409 {
			t.Fatal("accepted concurrent mutation")
		}
	}
	a.state.Busy = false
	a.state.Error = "proof failed"
	if w := request(a, "POST", "/api/advance", `{"step":0}`, nil); w.Code != 409 {
		t.Fatal("continued failed scenario")
	}
	a.state.Error = ""
	a.state.Next = len(steps)
	if w := request(a, "POST", "/api/advance", `{"step":8}`, nil); w.Code != 409 {
		t.Fatal("continued complete scenario")
	}
	a.bundle = []byte("finished archive")
	w = request(a, "GET", "/api/export", "", nil)
	if w.Code != 200 || w.Body.String() != "finished archive" {
		t.Fatal("export unavailable")
	}
	w = request(a, "POST", "/api/reset", `{}`, nil)
	if w.Code != 204 || a.state.Next != 0 || len(a.bundle) != 0 {
		t.Fatal("reset did not clear workflow and export")
	}
}
func TestZipExportPaths(t *testing.T) {
	data, err := zipExport(map[string][]byte{"reports/01/message.json": []byte("message"), "public-setup/vk.bin": []byte("public key")})
	if err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 2 {
		t.Fatal("wrong file count")
	}
	for _, f := range r.File {
		reader, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || len(b) == 0 {
			t.Fatal("invalid archived contents")
		}
	}
	if _, err = zipExport(map[string][]byte{"../wallet": []byte("secret")}); err == nil {
		t.Fatal("allowed parent traversal")
	}
}

func TestAsyncFailureAndReset(t *testing.T) {
	a, err := newApp(config{root: t.TempDir(), setup: t.TempDir(), pin: strings.Repeat("0", 64)}, "127.0.0.1:8787")
	if err != nil {
		t.Fatal(err)
	}
	if w := request(a, "POST", "/api/advance", `{"step":0}`, nil); w.Code != 202 {
		t.Fatalf("did not dispatch: %d", w.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		w := request(a, "GET", "/api/state", "", nil)
		var state view
		if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		if !state.Busy {
			if state.Error == "" || state.Next != 0 || state.Export || state.Run != "" || len(state.Reports) != 0 {
				t.Fatalf("failure reported success or spurious artifacts: %+v", state)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed load did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if w := request(a, "POST", "/api/advance", `{"step":0}`, nil); w.Code != 409 {
		t.Fatal("failed workflow restarted without reset")
	}
	if w := request(a, "POST", "/api/reset", `{}`, nil); w.Code != 204 {
		t.Fatal("could not reset after failure")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Error != "" || a.state.Next != 0 || a.state.Busy {
		t.Fatal("reset retained failed state")
	}
}

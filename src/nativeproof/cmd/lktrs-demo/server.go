package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var web embed.FS

type stepInfo struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

var steps = []stepInfo{
	{"建立协作组", "注册三位参与者、四台设备，签发成员快照。首次生成证明参数可能需要数分钟。"},
	{"提交第一份报告", "Alice 的上游传感器提交一份模拟水质报告，生成真实证明并独立校验。"},
	{"切换设备", "重新打开 Alice 的钱包，从另一台设备提交；检查共享计数和同一期关联。"},
	{"另一位参与者", "Bob 提交报告，验证其成员资格并比较两个用户的公开化名。"},
	{"用完三个额度", "Alice 提交第三份报告，再尝试第四次；检查正常钱包的额度限制。"},
	{"模拟恶意重用", "明确绕过钱包，重用第一个计数槽签署不同报告，再用两份有效证明追责。"},
	{"撤销全部设备", "撤销 Alice 的两个账号、更新成员快照，检查旧证明与新提交的不同结果。"},
	{"独立进程复核", "导出公开材料，用独立命令验签，并检查篡改消息和错误成员版本会被拒绝。"},
}

type check struct {
	Label  string `json:"label"`
	Result string `json:"result"`
	Detail string `json:"detail"`
	MS     int64  `json:"ms"`
}
type reportView struct {
	ID         int    `json:"id"`
	Message    string `json:"message"`
	Nym        string `json:"nym"`
	Serial     string `json:"serial"`
	Epoch      uint64 `json:"epoch"`
	ProofBytes int    `json:"proof_bytes"`
	ProveMS    int64  `json:"prove_ms"`
	VerifyMS   int64  `json:"verify_ms"`
	Decision   string `json:"decision"`
	TraceUser  string `json:"trace_user,omitempty"`
}
type view struct {
	Steps     []stepInfo   `json:"steps"`
	Next      int          `json:"next"`
	Busy      bool         `json:"busy"`
	Started   int64        `json:"started"`
	Phase     string       `json:"phase"`
	Error     string       `json:"error"`
	Token     string       `json:"token"`
	Run       string       `json:"run"`
	Issue     string       `json:"issue"`
	Pin       string       `json:"pin"`
	Epoch     uint64       `json:"epoch"`
	AliceUsed uint32       `json:"alice_used"`
	BobUsed   uint32       `json:"bob_used"`
	Revoked   bool         `json:"revoked"`
	Reports   []reportView `json:"reports"`
	Checks    []check      `json:"checks"`
	Export    bool         `json:"export"`
}
type app struct {
	mu          sync.Mutex
	engine      *engine // only the serialized worker accesses the engine
	state       view
	host, token string
	bundle      []byte
}

func newApp(c config, host string) (*app, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	a := &app{engine: &engine{config: c}, host: host, token: hex.EncodeToString(token[:])}
	a.state = view{Steps: steps, Token: a.token, Phase: "等待建立协作组"}
	return a, nil
}
func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.Host != a.host {
		http.Error(w, "unexpected Host", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+a.host {
		http.Error(w, "foreign origin", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/api/state":
			a.mu.Lock()
			defer a.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(a.state)
		case "/api/export":
			a.mu.Lock()
			bundle := a.bundle
			a.mu.Unlock()
			if len(bundle) == 0 {
				http.Error(w, "complete independent verification first", 409)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", `attachment; filename="lktrs-public-evidence.zip"`)
			_, _ = w.Write(bundle)
		case "/", "/app.js", "/style.css":
			name := strings.TrimPrefix(r.URL.Path, "/")
			if name == "" {
				name = "index.html"
			}
			data, err := web.ReadFile("web/" + name)
			if err != nil {
				http.Error(w, "asset unavailable", 500)
				return
			}
			mime := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}
			w.Header().Set("Content-Type", mime[name])
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/api/advance" && r.URL.Path != "/api/reset") {
		http.Error(w, "method or route not allowed", 405)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Demo-Token")), []byte(a.token)) != 1 {
		http.Error(w, "missing session token", 403)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "expected application/json", 415)
		return
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	stepInput, err := decodeAction(d)
	if err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		http.Error(w, "trailing request data", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.Busy {
		http.Error(w, "a step is already running", 409)
		return
	}
	if r.URL.Path == "/api/reset" {
		if stepInput != nil {
			http.Error(w, "reset takes no step", 400)
			return
		}
		a.engine.clearSecrets()
		a.engine = &engine{config: a.engine.config, loaded: a.engine.loaded}
		a.bundle = nil
		a.state = view{Steps: steps, Token: a.token, Phase: "等待建立协作组"}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if stepInput == nil || *stepInput != a.state.Next || a.state.Next >= len(steps) || a.state.Error != "" {
		http.Error(w, "unexpected step; reset after a failed run", 409)
		return
	}
	step := a.state.Next
	a.state.Busy = true
	a.state.Started = time.Now().UnixMilli()
	a.state.Phase = steps[step].Title
	go a.advance(step)
	w.WriteHeader(http.StatusAccepted)
}

// Reject duplicate fields as well as unknown fields: a workflow command must
// have one unambiguous interpretation at the HTTP boundary.
func decodeAction(d *json.Decoder) (*int, error) {
	open, err := d.Token()
	if err != nil || open != json.Delim('{') {
		return nil, errors.New("expected action object")
	}
	var step *int
	seen := false
	for d.More() {
		key, err := d.Token()
		if err != nil || key != "step" || seen {
			return nil, errors.New("unknown or duplicate action field")
		}
		seen = true
		if err = d.Decode(&step); err != nil {
			return nil, err
		}
	}
	if close, err := d.Token(); err != nil || close != json.Delim('}') {
		return nil, errors.New("unterminated action")
	}
	return step, nil
}
func (a *app) advance(step int) {
	err := a.engine.step(step, func(phase string) { a.mu.Lock(); a.state.Phase = phase; a.mu.Unlock() })
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.engine.snapshot()
	v.Steps = steps
	v.Token = a.token
	v.Next = step
	v.Phase = "步骤完成"
	if err != nil {
		v.Error = err.Error()
		v.Phase = "运行中止，请重新开始"
	} else {
		v.Next++
		if v.Next == len(steps) {
			v.Phase = "演示完成"
			a.bundle = a.engine.bundle
		}
	}
	a.state = v
}

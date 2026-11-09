package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

type harness struct {
	t       *testing.T
	store   *Store
	server  *Server
	handler http.Handler
}

func setup(t *testing.T) *harness {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service, err := New(store, "http://127.0.0.1:3002", "test")
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t, store, service, service.Handler()}
}
func (h *harness) request(method, path, body, contentType string, headers map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(method, h.server.Base+path, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w
}
func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
	}
	return result
}
func (h *harness) register(method string) map[string]any {
	h.t.Helper()
	body, _ := json.Marshal(map[string]any{"client_name": "Test MCP client", "redirect_uris": []string{h.server.Base + "/demo/callback"}, "token_endpoint_auth_method": method})
	w := h.request("POST", "/oauth/register", string(body), "application/json", nil)
	if w.Code != 201 {
		h.t.Fatalf("registration %d: %s", w.Code, w.Body.String())
	}
	return decode(h.t, w)
}

type flow struct {
	ID, Cookie, Verifier string
	Client               map[string]any
}

var flowPattern = regexp.MustCompile(`name="flow" value="([A-Za-z0-9_-]+)"`)

func (h *harness) start(c map[string]any) flow {
	h.t.Helper()
	verifier := randomToken()
	q := url.Values{"client_id": {c["client_id"].(string)}, "redirect_uri": {h.server.Base + "/demo/callback"}, "response_type": {"code"}, "state": {"test-state"}, "scope": {Scope}, "resource": {h.server.Resource}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}}
	w := h.request("GET", "/oauth/authorize?"+q.Encode(), "", "", nil)
	if w.Code != 200 {
		h.t.Fatalf("authorize %d: %s", w.Code, w.Body.String())
	}
	match := flowPattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		h.t.Fatal("missing login form")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		h.t.Fatal("missing secure flow cookie")
	}
	return flow{match[1], cookies[0].Name + "=" + cookies[0].Value, verifier, c}
}
func (h *harness) loginFlow(f flow, email, password string) *httptest.ResponseRecorder {
	return h.request("POST", "/oauth/authorize", url.Values{"flow": {f.ID}, "email": {email}, "password": {password}, "action": {"allow"}}.Encode(), "application/x-www-form-urlencoded", map[string]string{"Cookie": f.Cookie})
}
func (h *harness) code(f flow, email, password string) string {
	h.t.Helper()
	w := h.loginFlow(f, email, password)
	if w.Code != 303 {
		h.t.Fatalf("login %d: %s", w.Code, w.Body.String())
	}
	uri, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	if uri.Query().Get("state") != "test-state" || uri.Query().Get("iss") != h.server.Base {
		h.t.Fatal("state/issuer missing")
	}
	code := uri.Query().Get("code")
	if code == "" {
		h.t.Fatal("missing code")
	}
	return code
}
func (h *harness) tokenRequest(c map[string]any, values url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	headers := map[string]string{}
	values.Set("resource", h.server.Resource)
	method := c["token_endpoint_auth_method"].(string)
	if method == "client_secret_basic" {
		r := httptest.NewRequest("POST", "/", nil)
		r.SetBasicAuth(c["client_id"].(string), c["client_secret"].(string))
		headers["Authorization"] = r.Header.Get("Authorization")
	} else {
		values.Set("client_id", c["client_id"].(string))
		if method == "client_secret_post" {
			values.Set("client_secret", c["client_secret"].(string))
		}
	}
	return h.request("POST", "/oauth/token", values.Encode(), "application/x-www-form-urlencoded", headers)
}
func (h *harness) exchange(f flow, code string) *httptest.ResponseRecorder {
	return h.tokenRequest(f.Client, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {h.server.Base + "/demo/callback"}, "code_verifier": {f.Verifier}})
}
func (h *harness) connect(email, password, method string) (map[string]any, map[string]any) {
	h.t.Helper()
	c := h.register(method)
	f := h.start(c)
	w := h.exchange(f, h.code(f, email, password))
	if w.Code != 200 {
		h.t.Fatalf("token %d: %s", w.Code, w.Body.String())
	}
	return c, decode(h.t, w)
}
func (h *harness) profile(token string) *httptest.ResponseRecorder {
	headers := map[string]string{"Accept": "application/json, text/event-stream"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return h.request("POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_my_profile","arguments":{}}}`, "application/json", headers)
}
func rpcResult(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	text := w.Body.String()
	if strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "data:") {
				text = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				break
			}
		}
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		t.Fatalf("MCP parse: %v: %s", err, text)
	}
	if data["error"] != nil {
		t.Fatalf("MCP error: %+v", data)
	}
	result, ok := data["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing MCP result: %+v", data)
	}
	return result
}
func TestDiscoveryAndUnauthorized(t *testing.T) {
	h := setup(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/health", "/demo"} {
		w := h.request("GET", path, "", "", nil)
		if w.Code != 200 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	for _, method := range []string{"GET", "POST", "DELETE"} {
		w := h.request(method, "/mcp", "", "", nil)
		if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata=") {
			t.Fatalf("unprotected %s: %d", method, w.Code)
		}
	}
	if w := h.profile("made-up-token"); w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatal("invalid token accepted")
	}
	metadata := decode(t, h.request("GET", "/.well-known/oauth-authorization-server", "", "", nil))
	if metadata["registration_endpoint"] != h.server.Base+"/oauth/register" {
		t.Fatal("DCR not advertised")
	}
}
func TestProfilesAreIsolatedAndPasswordsHashed(t *testing.T) {
	h := setup(t)
	_, alice := h.connect("alice@example.com", "AliceDemo123!", "none")
	_, bob := h.connect("bob@example.com", "BobDemo123!", "client_secret_post")
	for _, test := range []struct {
		token map[string]any
		email string
	}{{alice, "alice@example.com"}, {bob, "bob@example.com"}, {alice, "alice@example.com"}} {
		w := h.profile(test.token["access_token"].(string))
		if w.Code != 200 {
			t.Fatalf("profile %d: %s", w.Code, w.Body.String())
		}
		response := rpcResult(t, w)
		profile := response["structuredContent"].(map[string]any)
		user := profile["user"].(map[string]any)
		if user["email"] != test.email {
			t.Fatalf("cross-user leak: %+v", user)
		}
		if strings.Contains(w.Body.String(), "password") {
			t.Fatal("password field leaked")
		}
	}
	var hash string
	if err := h.store.DB.QueryRow("SELECT password_hash FROM users WHERE email='alice@example.com'").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$2a$") {
		t.Fatalf("not bcrypt: %s", hash)
	}
	var count int
	err := h.store.DB.QueryRow("SELECT count(*) FROM tokens WHERE access_hash=? OR refresh_hash=?", alice["access_token"], alice["refresh_token"]).Scan(&count)
	if err != nil || count != 0 {
		t.Fatal("tokens stored in plaintext")
	}
	w := h.request("POST", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "application/json", map[string]string{"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + alice["access_token"].(string)})
	output := rpcResult(t, w)
	if len(output["tools"].([]any)) != 1 || !strings.Contains(w.Body.String(), Scope) {
		t.Fatal("missing profile tool/scope metadata")
	}
}
func TestPKCEBindingAndSingleUse(t *testing.T) {
	h := setup(t)
	c := h.register("none")
	f := h.start(c)
	code := h.code(f, "alice@example.com", "AliceDemo123!")
	wrong := f
	wrong.Verifier = randomToken()
	if w := h.exchange(wrong, code); w.Code != 400 {
		t.Fatal("wrong verifier accepted")
	}
	other := f
	other.Client = h.register("none")
	if w := h.exchange(other, code); w.Code != 400 {
		t.Fatal("code usable by another client")
	}
	w := h.exchange(f, code)
	if w.Code != 200 {
		t.Fatalf("valid verifier failed: %s", w.Body.String())
	}
	if w := h.exchange(f, code); w.Code != 400 {
		t.Fatal("authorization code replay accepted")
	}
	if w := h.loginFlow(f, "alice@example.com", "AliceDemo123!"); w.Code != 403 {
		t.Fatal("login flow replay accepted")
	}
	f = h.start(c)
	code = h.code(f, "alice@example.com", "AliceDemo123!")
	w = h.tokenRequest(c, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://evil.example/callback"}, "code_verifier": {f.Verifier}})
	if w.Code != 400 {
		t.Fatal("redirect mismatch accepted")
	}
	if _, err := h.store.DB.Exec("UPDATE codes SET expires=0"); err != nil {
		t.Fatal(err)
	}
	if w := h.exchange(f, code); w.Code != 400 {
		t.Fatal("expired code accepted")
	}
}
func TestLoginValidationCSRFAndDenial(t *testing.T) {
	h := setup(t)
	c := h.register("none")
	f := h.start(c)
	if w := h.loginFlow(f, "alice@example.com", "wrong"); w.Code != 200 || !strings.Contains(w.Body.String(), "Sign-in failed") {
		t.Fatal("bad password accepted")
	}
	if w := h.loginFlow(f, "missing@example.com", "wrong"); w.Code != 200 || !strings.Contains(w.Body.String(), "Sign-in failed") {
		t.Fatal("missing user accepted")
	}
	body := url.Values{"flow": {f.ID}, "email": {"alice@example.com"}, "password": {"AliceDemo123!"}}.Encode()
	if w := h.request("POST", "/oauth/authorize", body, "application/x-www-form-urlencoded", nil); w.Code != 403 {
		t.Fatal("missing CSRF cookie accepted")
	}
	if w := h.request("POST", "/oauth/authorize", body, "application/x-www-form-urlencoded", map[string]string{"Cookie": f.Cookie, "Origin": "https://evil.example"}); w.Code != 403 {
		t.Fatal("cross-origin login accepted")
	}
	w := h.request("POST", "/oauth/authorize", url.Values{"flow": {f.ID}, "action": {"deny"}}.Encode(), "application/x-www-form-urlencoded", map[string]string{"Cookie": f.Cookie})
	if w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "error=access_denied") {
		t.Fatal("consent denial failed")
	}
	f = h.start(c)
	for i := 0; i < 5; i++ {
		h.loginFlow(f, "alice@example.com", "wrong")
	}
	if w := h.loginFlow(f, "alice@example.com", "AliceDemo123!"); w.Code != 200 {
		t.Fatal("account lock bypassed")
	}
}
func TestRefreshRotationReplayAndRevocation(t *testing.T) {
	h := setup(t)
	c, tokens := h.connect("alice@example.com", "AliceDemo123!", "none")
	refresh := func(value string) *httptest.ResponseRecorder {
		return h.tokenRequest(c, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {value}})
	}
	w := refresh(tokens["refresh_token"].(string))
	if w.Code != 200 {
		t.Fatalf("refresh failed: %s", w.Body.String())
	}
	next := decode(t, w)
	if next["access_token"] == tokens["access_token"] || next["refresh_token"] == tokens["refresh_token"] {
		t.Fatal("tokens not rotated")
	}
	if h.profile(tokens["access_token"].(string)).Code != 401 {
		t.Fatal("old access token not revoked")
	}
	if h.profile(next["access_token"].(string)).Code != 200 {
		t.Fatal("new access rejected")
	}
	if refresh(tokens["refresh_token"].(string)).Code != 400 {
		t.Fatal("refresh replay accepted")
	}
	if h.profile(next["access_token"].(string)).Code != 401 {
		t.Fatal("refresh replay did not revoke family")
	}
	c, tokens = h.connect("bob@example.com", "BobDemo123!", "none")
	w = h.request("POST", "/oauth/revoke", url.Values{"client_id": {c["client_id"].(string)}, "token": {tokens["refresh_token"].(string)}}.Encode(), "application/x-www-form-urlencoded", nil)
	if w.Code != 200 || h.profile(tokens["access_token"].(string)).Code != 401 {
		t.Fatal("revocation failed")
	}
}
func TestExpiryAudienceScopeAndDisabledUser(t *testing.T) {
	h := setup(t)
	_, tokens := h.connect("alice@example.com", "AliceDemo123!", "none")
	token := tokens["access_token"].(string)
	updates := []string{"access_expires=0", "resource='https://other.example/mcp'", "scope='other:read'", "revoked=1"}
	for _, update := range updates {
		if _, err := h.store.DB.Exec("UPDATE tokens SET " + update); err != nil {
			t.Fatal(err)
		}
		w := h.profile(token)
		expected := 401
		if strings.HasPrefix(update, "scope") {
			expected = 403
		}
		if w.Code != expected {
			t.Fatalf("accepted %s: %d", update, w.Code)
		}
		if _, err := h.store.DB.Exec("UPDATE tokens SET access_expires=?,resource=?,scope=?,revoked=0", time.Now().Add(time.Hour).Unix(), h.server.Resource, Scope); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.store.DB.Exec("UPDATE users SET disabled=1 WHERE email='alice@example.com'"); err != nil {
		t.Fatal(err)
	}
	if h.profile(token).Code != 401 {
		t.Fatal("disabled user accepted")
	}
}
func TestRegistrationAndAuthorizationValidation(t *testing.T) {
	h := setup(t)
	for _, uri := range []string{"http://evil.example/callback", "https://example.com/callback#fragment", "javascript:alert(1)", "https://user:password@example.com/callback"} {
		body, _ := json.Marshal(map[string]any{"redirect_uris": []string{uri}})
		if w := h.request("POST", "/oauth/register", string(body), "application/json", nil); w.Code != 400 {
			t.Fatalf("accepted %s", uri)
		}
	}
	c := h.register("none")
	base := url.Values{"client_id": {c["client_id"].(string)}, "redirect_uri": {h.server.Base + "/demo/callback"}, "response_type": {"code"}, "scope": {Scope}, "resource": {h.server.Resource}, "code_challenge": {challenge(randomToken())}, "code_challenge_method": {"S256"}}
	for key, value := range map[string]string{"redirect_uri": "https://evil.example/cb", "code_challenge_method": "plain", "resource": "https://other.example/mcp", "scope": "admin", "response_type": "token"} {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		q.Set(key, value)
		w := h.request("GET", "/oauth/authorize?"+q.Encode(), "", "", nil)
		if w.Code != 400 || w.Header().Get("Location") != "" {
			t.Fatalf("invalid %s accepted", key)
		}
	}
	w := h.request("POST", "/oauth/token", url.Values{"client_id": {c["client_id"].(string)}, "grant_type": {"password"}, "resource": {h.server.Resource}}.Encode(), "application/x-www-form-urlencoded", nil)
	if decode(t, w)["error"] != "unsupported_grant_type" {
		t.Fatal("password grant supported")
	}
}
func TestConfidentialClientSecret(t *testing.T) {
	h := setup(t)
	c, tokens := h.connect("alice@example.com", "AliceDemo123!", "client_secret_basic")
	bad := map[string]any{}
	for k, v := range c {
		bad[k] = v
	}
	bad["client_secret"] = "wrong"
	w := h.tokenRequest(bad, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}})
	if w.Code != 401 {
		t.Fatal("wrong client secret accepted")
	}
}
func TestConcurrentCodeRedemption(t *testing.T) {
	h := setup(t)
	f := h.start(h.register("none"))
	code := h.code(f, "alice@example.com", "AliceDemo123!")
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- h.exchange(f, code).Code }()
	}
	wg.Wait()
	close(codes)
	success := 0
	failure := 0
	for status := range codes {
		if status == 200 {
			success++
		}
		if status == 400 {
			failure++
		}
	}
	if success != 1 || failure != 1 {
		t.Fatal("authorization code not atomically single use")
	}
}
func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persistent.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err = store.DB.QueryRow("SELECT count(*) FROM users").Scan(&count); err != nil || count != 2 {
		t.Fatal("mock users duplicated on restart")
	}
}
func TestRealHTTPMCPClient(t *testing.T) {
	h := setup(t)
	_, tokens := h.connect("bob@example.com", "BobDemo123!", "none")
	ts := httptest.NewServer(h.handler)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.NewStreamableHttpClient(ts.URL+"/mcp", transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + tokens["access_token"].(string)}))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	initialize := mcp.InitializeRequest{}
	initialize.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initialize.Params.ClientInfo = mcp.Implementation{Name: "auth-test", Version: "1"}
	if _, err = c.Initialize(ctx, initialize); err != nil {
		t.Fatal(err)
	}
	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil || len(tools.Tools) != 1 {
		t.Fatalf("discovery: %v", err)
	}
	r, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "get_my_profile", Arguments: map[string]any{}}})
	if err != nil || r.IsError {
		t.Fatalf("profile: %v %+v", err, r)
	}
	raw, _ := json.Marshal(r.StructuredContent)
	if !bytes.Contains(raw, []byte("bob@example.com")) {
		t.Fatal("wrong profile over HTTP")
	}
	if _, err = h.store.DB.Exec("UPDATE tokens SET revoked=1"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ListTools(ctx, mcp.ListToolsRequest{}); err == nil {
		t.Fatal("subsequent request not validated")
	}
}
func TestOriginAndInputValidation(t *testing.T) {
	for _, value := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com?x=1"} {
		if _, err := baseURL(value); err == nil {
			t.Fatalf("invalid origin %s", value)
		}
	}
	for _, value := range []string{"http://127.0.0.1:3002", "https://auth.example.com"} {
		if _, err := baseURL(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExternalCallbackPolicyAndHostValidation(t *testing.T) {
	h := setup(t)
	body := `{"client_name":"External MCP host","redirect_uris":["https://host.example.com/oauth/callback"],"token_endpoint_auth_method":"none"}`
	w := h.request("POST", "/oauth/register", body, "application/json", nil)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	c := decode(t, w)
	q := url.Values{"client_id": {c["client_id"].(string)}, "redirect_uri": {"https://host.example.com/oauth/callback"}, "response_type": {"code"}, "resource": {h.server.Resource}, "code_challenge": {challenge(randomToken())}, "code_challenge_method": {"S256"}}
	w = h.request("GET", "/oauth/authorize?"+q.Encode(), "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self' https://host.example.com;") {
		t.Fatal("CSP blocks external host callback")
	}
	if w.Header().Get("Referrer-Policy") == "no-referrer" {
		t.Fatal("form POST origin will be suppressed")
	}
	r := httptest.NewRequest("GET", "http://evil.example/health", nil)
	w = httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("untrusted Host accepted")
	}
}

func TestKubernetesHostAndGatewayPrefix(t *testing.T) {
	h := setup(t)
	service, err := New(h.store, "https://centermcp.com/mcp/centerauth", "test", "*.boodabest.svc.cluster.local")
	if err != nil {
		t.Fatal(err)
	}
	h.server = service
	h.handler = service.Handler()
	for host, want := range map[string]int{"mcp-revision.boodabest.svc.cluster.local:8000": 401, "attacker.example": 403, "mcp-revision.boodabest.svc.cluster.local.attacker.example:8000": 403} {
		r := httptest.NewRequest("POST", "http://"+host+"/mcp", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("Host %s: %d want %d", host, w.Code, want)
		}
		if w.Code == 401 && !strings.Contains(w.Header().Get("WWW-Authenticate"), service.Base+"/.well-known/oauth-protected-resource/mcp") {
			t.Fatal("incorrect public metadata URL")
		}
	}
	w := h.request("GET", "/demo", "", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `src="https://centermcp.com/mcp/centerauth/demo.js"`) {
		t.Fatal("demo prefix missing")
	}
	c := h.register("none")
	f := h.start(c)
	w = h.exchange(f, h.code(f, "alice@example.com", "AliceDemo123!"))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	tokens := decode(t, w)
	w = h.profile(tokens["access_token"].(string))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Fatal("prefixed OAuth flow failed")
	}
	if service.Resource != "https://centermcp.com/mcp/centerauth" {
		t.Fatal("audience must match gateway endpoint")
	}
	for _, kind := range []string{"oauth-protected-resource", "oauth-authorization-server"} {
		r := httptest.NewRequest("GET", "https://centermcp.com/.well-known/"+kind+"/mcp/centerauth", nil)
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("RFC discovery %s: %d", kind, w.Code)
		}
	}
}
func TestAllowedHostConfiguration(t *testing.T) {
	h := setup(t)
	for _, host := range []string{"*", "https://internal.example", "*.svc.cluster.local/evil", "*.svc.*"} {
		if _, err := New(h.store, "https://auth.example.com", "test", host); err == nil {
			t.Fatalf("invalid host allowlist accepted %s", host)
		}
	}
	for _, base := range []string{"https://auth.example.com/foo/../bar", "https://auth.example.com/foo//bar"} {
		if _, err := New(h.store, base, "test"); err == nil {
			t.Fatalf("invalid path accepted: %s", base)
		}
	}
}

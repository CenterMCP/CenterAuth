package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type registration struct {
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AuthMethod    string   `json:"token_endpoint_auth_method"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
}
type clientRecord struct{ ID, Name, Redirects, Method, SecretHash string }

func (s *Server) client(id string) (clientRecord, error) {
	var c clientRecord
	err := s.Store.DB.QueryRow("SELECT id,name,redirect_uris,auth_method,secret_hash FROM clients WHERE id=?", id).Scan(&c.ID, &c.Name, &c.Redirects, &c.Method, &c.SecretHash)
	return c, err
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var input registration
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		oauthError(w, 400, "invalid_client_metadata", "Expected a JSON registration object")
		return
	}
	if len(input.RedirectURIs) == 0 || len(input.RedirectURIs) > 10 {
		oauthError(w, 400, "invalid_redirect_uri", "Supply 1 to 10 redirect URIs")
		return
	}
	for _, uri := range input.RedirectURIs {
		if len(uri) > 2048 || !validRedirect(uri) {
			oauthError(w, 400, "invalid_redirect_uri", "Redirect URI must use HTTPS or loopback HTTP, without fragments")
			return
		}
	}
	if input.ClientName == "" {
		input.ClientName = "MCP client"
	}
	if len(input.ClientName) > 200 {
		oauthError(w, 400, "invalid_client_metadata", "Client name is too long")
		return
	}
	if input.AuthMethod == "" {
		input.AuthMethod = "client_secret_basic"
	}
	switch input.AuthMethod {
	case "none", "client_secret_post", "client_secret_basic":
	default:
		oauthError(w, 400, "invalid_client_metadata", "Unsupported token endpoint authentication method")
		return
	}
	for _, grant := range input.GrantTypes {
		if grant != "authorization_code" && grant != "refresh_token" {
			oauthError(w, 400, "invalid_client_metadata", "Only authorization_code and refresh_token are supported")
			return
		}
	}
	for _, response := range input.ResponseTypes {
		if response != "code" {
			oauthError(w, 400, "invalid_client_metadata", "Only response_type code is supported")
			return
		}
	}
	id, secret := randomToken(), ""
	if input.AuthMethod != "none" {
		secret = randomToken()
	}
	redirects, _ := json.Marshal(input.RedirectURIs)
	issued := time.Now().Unix()
	if _, err := s.Store.DB.Exec("INSERT INTO clients(id,name,redirect_uris,auth_method,secret_hash,created_at) VALUES(?,?,?,?,?,?)", id, input.ClientName, string(redirects), input.AuthMethod, digest(secret), issued); err != nil {
		oauthError(w, 500, "server_error", "Could not register client")
		return
	}
	response := map[string]any{"client_id": id, "client_id_issued_at": issued, "client_name": input.ClientName, "redirect_uris": input.RedirectURIs, "token_endpoint_auth_method": input.AuthMethod, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": Scope}
	if secret != "" {
		response["client_secret"] = secret
		response["client_secret_expires_at"] = 0
	}
	writeJSON(w, 201, response)
}

type authRequest struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Redirect   string `json:"redirect_uri"`
	State      string `json:"state"`
	Challenge  string `json:"challenge"`
	Resource   string `json:"resource"`
	Scope      string `json:"scope"`
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for _, values := range query {
		if len(values) != 1 {
			oauthError(w, 400, "invalid_request", "Duplicate authorization parameters")
			return
		}
	}
	client, err := s.client(query.Get("client_id"))
	if err != nil {
		oauthError(w, 400, "invalid_client", "Unknown client; register it first")
		return
	}
	var redirects []string
	_ = json.Unmarshal([]byte(client.Redirects), &redirects)
	valid := false
	for _, uri := range redirects {
		if uri == query.Get("redirect_uri") {
			valid = true
		}
	}
	if !valid {
		oauthError(w, 400, "invalid_request", "redirect_uri must exactly match a registered URI")
		return
	}
	if query.Get("response_type") != "code" {
		oauthError(w, 400, "unsupported_response_type", "Use response_type=code")
		return
	}
	decoded, err := base64.RawURLEncoding.DecodeString(query.Get("code_challenge"))
	if query.Get("code_challenge_method") != "S256" || err != nil || len(decoded) != 32 {
		oauthError(w, 400, "invalid_request", "PKCE S256 with a SHA-256 challenge is required")
		return
	}
	if query.Get("resource") != s.Resource {
		oauthError(w, 400, "invalid_target", "resource must be "+s.Resource)
		return
	}
	scope := query.Get("scope")
	if scope == "" {
		scope = Scope
	}
	if scope != Scope {
		oauthError(w, 400, "invalid_scope", "Only "+Scope+" is supported")
		return
	}
	if len(query.Get("state")) > 2048 {
		oauthError(w, 400, "invalid_request", "state is too long")
		return
	}
	request := authRequest{client.ID, client.Name, query.Get("redirect_uri"), query.Get("state"), query.Get("code_challenge"), s.Resource, scope}
	flow, csrf := randomToken(), randomToken()
	raw, _ := json.Marshal(request)
	if _, err := s.Store.DB.Exec("INSERT INTO login_flows(id,csrf_hash,request_json,expires) VALUES(?,?,?,?)", flow, digest(csrf), string(raw), time.Now().Add(10*time.Minute).Unix()); err != nil {
		oauthError(w, 500, "server_error", "Could not start sign-in")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "centerauth_" + flow, Value: csrf, Path: s.Prefix + "/oauth/authorize", HttpOnly: true, Secure: strings.HasPrefix(s.Base, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 600})
	s.renderLogin(w, flow, request, "")
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "Invalid sign-in form")
		return
	}
	flow := r.PostForm.Get("flow")
	if len(flow) != 43 {
		oauthError(w, 400, "invalid_request", "Invalid sign-in flow")
		return
	}
	cookie, err := r.Cookie("centerauth_" + flow)
	if err != nil {
		oauthError(w, 403, "access_denied", "Sign-in cookie missing; restart authorization")
		return
	}
	var csrfHash, raw string
	err = s.Store.DB.QueryRow("SELECT csrf_hash,request_json FROM login_flows WHERE id=? AND expires>?", flow, time.Now().Unix()).Scan(&csrfHash, &raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(csrfHash), []byte(digest(cookie.Value))) != 1 {
		oauthError(w, 403, "access_denied", "Sign-in expired or browser validation failed")
		return
	}
	var request authRequest
	if json.Unmarshal([]byte(raw), &request) != nil {
		oauthError(w, 500, "server_error", "Invalid stored flow")
		return
	}
	if r.PostForm.Get("action") == "deny" {
		if _, err := s.Store.DB.Exec("DELETE FROM login_flows WHERE id=?", flow); err != nil {
			oauthError(w, 500, "server_error", "Could not cancel flow")
			return
		}
		s.clearFlow(w, flow)
		s.redirect(w, r, request, map[string]string{"error": "access_denied"})
		return
	}
	user, err := s.Store.login(r.PostForm.Get("email"), r.PostForm.Get("password"))
	if err != nil {
		s.renderLogin(w, flow, request, "Sign-in failed. Check your email and password, or wait five minutes if temporarily locked.")
		return
	}
	code := randomToken()
	tx, err := s.Store.DB.Begin()
	if err != nil {
		oauthError(w, 500, "server_error", "Could not complete sign-in")
		return
	}
	defer tx.Rollback()
	deleted, err := tx.Exec("DELETE FROM login_flows WHERE id=? AND expires>?", flow, time.Now().Unix())
	if err != nil {
		oauthError(w, 500, "server_error", "Could not complete flow")
		return
	}
	count, _ := deleted.RowsAffected()
	if count != 1 {
		oauthError(w, 400, "invalid_request", "Sign-in flow already used")
		return
	}
	_, err = tx.Exec("INSERT INTO codes(hash,user_id,client_id,redirect_uri,challenge,resource,scope,expires) VALUES(?,?,?,?,?,?,?,?)", digest(code), user.ID, request.ClientID, request.Redirect, request.Challenge, request.Resource, request.Scope, time.Now().Add(2*time.Minute).Unix())
	if err != nil {
		oauthError(w, 500, "server_error", "Could not issue code")
		return
	}
	if err = tx.Commit(); err != nil {
		oauthError(w, 500, "server_error", "Could not complete sign-in")
		return
	}
	s.clearFlow(w, flow)
	s.redirect(w, r, request, map[string]string{"code": code, "iss": s.Base})
}
func (s *Server) clearFlow(w http.ResponseWriter, flow string) {
	http.SetCookie(w, &http.Cookie{Name: "centerauth_" + flow, Path: s.Prefix + "/oauth/authorize", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(s.Base, "https://"), SameSite: http.SameSiteLaxMode})
}
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, request authRequest, extra map[string]string) {
	uri, _ := url.Parse(request.Redirect)
	q := uri.Query()
	if request.State != "" {
		q.Set("state", request.State)
	}
	for key, value := range extra {
		q.Set(key, value)
	}
	uri.RawQuery = q.Encode()
	http.Redirect(w, r, uri.String(), http.StatusSeeOther)
}
func (s *Server) authenticateClient(r *http.Request) (clientRecord, error) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	basicID, basicSecret, basic := r.BasicAuth()
	if r.Header.Get("Authorization") != "" && !basic {
		return clientRecord{}, errors.New("invalid client authentication")
	}
	if basic {
		if id != "" || secret != "" {
			return clientRecord{}, errors.New("multiple client authentication methods")
		}
		id, secret = basicID, basicSecret
	}
	client, err := s.client(id)
	if err != nil {
		return clientRecord{}, errors.New("unknown client")
	}
	switch client.Method {
	case "none":
		if basic || secret != "" {
			return clientRecord{}, errors.New("public client must not send a secret")
		}
	case "client_secret_basic":
		if !basic || subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(digest(secret))) != 1 {
			return clientRecord{}, errors.New("invalid client secret")
		}
	case "client_secret_post":
		if basic || subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(digest(secret))) != 1 {
			return clientRecord{}, errors.New("invalid client secret")
		}
	default:
		return clientRecord{}, errors.New("unsupported client authentication")
	}
	return client, nil
}
func parseTokenForm(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		oauthError(w, 400, "invalid_request", "Use application/x-www-form-urlencoded")
		return false
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "Invalid form body")
		return false
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			oauthError(w, 400, "invalid_request", "Duplicate form parameters")
			return false
		}
	}
	return true
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if !parseTokenForm(w, r) {
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="CenterAuth"`)
		oauthError(w, 401, "invalid_client", "Client authentication failed")
		return
	}
	if r.PostForm.Get("resource") != s.Resource {
		oauthError(w, 400, "invalid_target", "resource must be "+s.Resource)
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, client)
	case "refresh_token":
		s.refresh(w, r, client)
	default:
		oauthError(w, 400, "unsupported_grant_type", "Use authorization_code or refresh_token; password grants are not supported")
	}
}
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, client clientRecord) {
	verifier := r.PostForm.Get("code_verifier")
	if !validVerifier(verifier) {
		oauthError(w, 400, "invalid_grant", "Invalid PKCE verifier")
		return
	}
	tx, err := s.Store.DB.Begin()
	if err != nil {
		oauthError(w, 500, "server_error", "Could not exchange code")
		return
	}
	defer tx.Rollback()
	var userID int64
	var expected, scope string
	err = tx.QueryRow(`DELETE FROM codes WHERE hash=? AND client_id=? AND redirect_uri=? AND resource=? AND expires>? RETURNING user_id,challenge,scope`, digest(r.PostForm.Get("code")), client.ID, r.PostForm.Get("redirect_uri"), s.Resource, time.Now().Unix()).Scan(&userID, &expected, &scope)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(challenge(verifier))) != 1 {
		oauthError(w, 400, "invalid_grant", "Code expired, already used, or PKCE/client/redirect mismatch")
		return
	}
	var disabled int
	if err = tx.QueryRow("SELECT disabled FROM users WHERE id=?", userID).Scan(&disabled); err != nil || disabled != 0 {
		oauthError(w, 400, "invalid_grant", "User is unavailable")
		return
	}
	tokens, err := issue(tx, userID, client.ID, s.Resource, scope, "")
	if err != nil {
		oauthError(w, 500, "server_error", "Could not issue tokens")
		return
	}
	if err = tx.Commit(); err != nil {
		oauthError(w, 500, "server_error", "Could not issue tokens")
		return
	}
	writeJSON(w, 200, tokens)
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request, client clientRecord) {
	tx, err := s.Store.DB.Begin()
	if err != nil {
		oauthError(w, 500, "server_error", "Could not refresh token")
		return
	}
	defer tx.Rollback()
	var family, scope string
	var userID, expires int64
	var revoked, disabled int
	err = tx.QueryRow(`SELECT t.family,t.scope,t.user_id,t.refresh_expires,t.revoked,u.disabled FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.refresh_hash=? AND t.client_id=? AND t.resource=?`, digest(r.PostForm.Get("refresh_token")), client.ID, s.Resource).Scan(&family, &scope, &userID, &expires, &revoked, &disabled)
	if err != nil {
		oauthError(w, 400, "invalid_grant", "Unknown refresh token")
		return
	}
	if revoked != 0 {
		_, err = tx.Exec("UPDATE tokens SET revoked=1 WHERE family=?", family)
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			oauthError(w, 500, "server_error", "Could not revoke replayed token family")
			return
		}
		oauthError(w, 400, "invalid_grant", "Refresh token already used; token family revoked")
		return
	}
	if expires <= time.Now().Unix() || disabled != 0 {
		oauthError(w, 400, "invalid_grant", "Refresh token expired or user unavailable")
		return
	}
	if requested := r.PostForm.Get("scope"); requested != "" && requested != scope {
		oauthError(w, 400, "invalid_scope", "Cannot expand granted scope")
		return
	}
	if _, err = tx.Exec("UPDATE tokens SET revoked=1 WHERE refresh_hash=?", digest(r.PostForm.Get("refresh_token"))); err != nil {
		oauthError(w, 500, "server_error", "Could not rotate token")
		return
	}
	tokens, err := issue(tx, userID, client.ID, s.Resource, scope, family)
	if err != nil {
		oauthError(w, 500, "server_error", "Could not rotate token")
		return
	}
	if err = tx.Commit(); err != nil {
		oauthError(w, 500, "server_error", "Could not rotate token")
		return
	}
	writeJSON(w, 200, tokens)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if !parseTokenForm(w, r) {
		return
	}
	client, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, 401, "invalid_client", "Client authentication failed")
		return
	}
	hash := digest(r.PostForm.Get("token"))
	_, err = s.Store.DB.Exec(`UPDATE tokens SET revoked=1 WHERE family IN (SELECT family FROM tokens WHERE (access_hash=? OR refresh_hash=?) AND client_id=?)`, hash, hash, client.ID)
	if err != nil {
		oauthError(w, 500, "server_error", "Could not revoke token")
		return
	}
	w.WriteHeader(200)
}

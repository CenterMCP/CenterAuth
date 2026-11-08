// Package auth demonstrates a co-hosted OAuth authorization server and protected MCP resource server.
package auth

import (
	"context"
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

//go:embed login.html
var loginHTML string

//go:embed demo.html
var demoHTML string

//go:embed demo.js
var demoJS string

var loginTemplate = template.Must(template.New("login").Parse(loginHTML))

type userContextKey struct{}
type Server struct {
	Store          *Store
	Base, Resource string
	MCP            *server.MCPServer
	Transport      *server.StreamableHTTPServer
}
type Profile struct {
	User    User   `json:"user"`
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

func New(store *Store, publicURL, version string) (*Server, error) {
	base, err := baseURL(publicURL)
	if err != nil {
		return nil, err
	}
	s := &Server{Store: store, Base: base, Resource: base + "/mcp"}
	s.MCP = server.NewMCPServer("CenterAuth", version, server.WithToolCapabilities(false))
	tool := mcp.NewTool("get_my_profile", mcp.WithDescription("Return the authenticated user's profile from SQLite. Identity comes exclusively from the validated OAuth bearer token on this request. Never ask for passwords or tokens in chat."), mcp.WithSchemaAdditionalProperties(false), mcp.WithOutputSchema[Profile](), mcp.WithReadOnlyHintAnnotation(true), mcp.WithDestructiveHintAnnotation(false), mcp.WithIdempotentHintAnnotation(true), mcp.WithOpenWorldHintAnnotation(false))
	tool.Meta = mcp.NewMetaFromMap(map[string]any{"securitySchemes": []map[string]any{{"type": "oauth2", "scopes": []string{Scope}}}})
	s.MCP.AddTool(tool, s.GetMyProfile)
	// No shared MCP session identity: the HTTP middleware authenticates each request.
	s.Transport = server.NewStreamableHTTPServer(s.MCP, server.WithStateLess(true), server.WithDisableLocalhostProtection(true))
	return s, nil
}
func (s *Server) GetMyProfile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	user, ok := ctx.Value(userContextKey{}).(User)
	if !ok {
		return mcp.NewToolResultError("Authentication required"), nil
	}
	if len(req.GetArguments()) != 0 {
		return mcp.NewToolResultError("get_my_profile accepts no arguments; user identity is determined by the access token"), nil
	}
	profile := Profile{user, Scope, "Authenticated request confirmed by CenterAuth."}
	raw, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultStructured(profile, string(raw)), nil
}
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(r.Header.Values("Authorization")) != 1 {
			s.challenge(w, "", http.StatusUnauthorized)
			return
		}
		user, scope, err := s.Store.ValidateAccess(parts[1], s.Resource)
		if err != nil {
			s.challenge(w, "invalid_token", http.StatusUnauthorized)
			return
		}
		if scope != Scope {
			s.challenge(w, "insufficient_scope", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
	})
}
func (s *Server) challenge(w http.ResponseWriter, code string, status int) {
	challenge := `Bearer resource_metadata="` + s.Base + `/.well-known/oauth-protected-resource/mcp", scope="` + Scope + `"`
	if code != "" {
		challenge += `, error="` + code + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	if code == "" {
		code = "unauthorized"
	}
	oauthError(w, status, code, "A valid CenterAuth access token is required")
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	metadata := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": s.Resource, "resource_name": "CenterAuth MCP", "authorization_servers": []string{s.Base}, "scopes_supported": []string{Scope}, "bearer_methods_supported": []string{"header"}})
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", metadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", metadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer": s.Base, "authorization_endpoint": s.Base + "/oauth/authorize", "token_endpoint": s.Base + "/oauth/token", "registration_endpoint": s.Base + "/oauth/register", "revocation_endpoint": s.Base + "/oauth/revoke",
			"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "scopes_supported": []string{Scope}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"}, "revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"}, "authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/authorize", s.login)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	mux.Handle("/mcp", s.requireAuth(s.Transport))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Store.DB.PingContext(r.Context()); err != nil {
			writeJSON(w, 503, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, 200, map[string]string{"name": "CenterAuth", "status": "ok"})
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/demo", http.StatusSeeOther) })
	demo := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(demoHTML))
	}
	mux.HandleFunc("GET /demo", demo)
	mux.HandleFunc("GET /demo/callback", demo)
	mux.HandleFunc("GET /demo.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write([]byte(demoJS))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate Host here so a configured public HTTPS origin also works behind a local reverse proxy.
		expected, _ := url.Parse(s.Base)
		incoming, err := url.Parse("http://" + r.Host)
		if err != nil || incoming.User != nil || (!strings.EqualFold(r.Host, expected.Host) && !loopback(incoming.Hostname())) {
			http.Error(w, "Host not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Method == http.MethodPost && r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.Base {
			http.Error(w, "Origin not allowed", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) renderLogin(w http.ResponseWriter, flow string, request authRequest, message string) {
	// Browsers may apply form-action to the 303 redirect as well as the POST.
	// Allow only the already-registered, validated callback origin for this flow.
	callback, _ := url.Parse(request.Redirect)
	policy := w.Header().Get("Content-Security-Policy")
	w.Header().Set("Content-Security-Policy", strings.Replace(policy, "form-action 'self';", "form-action 'self' "+callback.Scheme+"://"+callback.Host+";", 1))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, struct{ Flow, Client, Scope, Resource, Error string }{flow, request.ClientName, request.Scope, request.Resource, message})
}

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const Scope = "profile:read"
const AccessLifetime = 15 * time.Minute
const RefreshLifetime = 7 * 24 * time.Hour

// User is the only user information exposed to MCP. Password hashes never leave SQLite.
type User struct {
	ID        int64  `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}
type Store struct {
	DB        *sql.DB
	dummyHash []byte
}

func Open(path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: absolute}
	q := url.Values{"_foreign_keys": {"on"}, "_busy_timeout": {"5000"}, "_journal_mode": {"WAL"}}
	uri.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	s.dummyHash, err = bcrypt.GenerateFromPassword([]byte("unknown-user-timing-placeholder"), bcrypt.DefaultCost)
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, user := range []struct{ email, name, password string }{{"alice@example.com", "Alice Demo", "AliceDemo123!"}, {"bob@example.com", "Bob Demo", "BobDemo123!"}} {
		var exists int
		err = db.QueryRow("SELECT count(*) FROM users WHERE email=?", user.email).Scan(&exists)
		if err != nil {
			db.Close()
			return nil, err
		}
		if exists > 0 {
			continue
		}
		passwordHash, hashErr := bcrypt.GenerateFromPassword([]byte(user.password), bcrypt.DefaultCost)
		if hashErr != nil {
			db.Close()
			return nil, hashErr
		}
		if _, err = db.Exec("INSERT OR IGNORE INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)", user.email, user.name, string(passwordHash), time.Now().UTC().Format(time.RFC3339)); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Store) login(email, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var user User
	var passwordHash string
	var locked int64
	err := s.DB.QueryRow("SELECT id,email,name,created_at,password_hash,locked_until FROM users WHERE email=? AND disabled=0", email).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt, &passwordHash, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password))
		return User{}, errors.New("invalid credentials")
	}
	if err != nil {
		return User{}, err
	}
	if locked > time.Now().Unix() {
		return User{}, errors.New("invalid credentials")
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
		_, err = s.DB.Exec("UPDATE users SET failed_attempts=CASE WHEN locked_until>0 AND locked_until<=? THEN 1 ELSE failed_attempts+1 END, locked_until=CASE WHEN failed_attempts>=4 AND (locked_until=0 OR locked_until>?) THEN ? ELSE 0 END WHERE id=?", time.Now().Unix(), time.Now().Unix(), time.Now().Add(5*time.Minute).Unix(), user.ID)
		if err != nil {
			return User{}, err
		}
		return User{}, errors.New("invalid credentials")
	}
	_, err = s.DB.Exec("UPDATE users SET failed_attempts=0,locked_until=0 WHERE id=?", user.ID)
	return user, err
}

func (s *Store) ValidateAccess(token, resource string) (User, string, error) {
	var user User
	var scope string
	err := s.DB.QueryRow(`SELECT u.id,u.email,u.name,u.created_at,t.scope FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.access_hash=? AND t.resource=? AND t.revoked=0 AND t.access_expires>? AND u.disabled=0`, digest(token), resource, time.Now().Unix()).Scan(&user.ID, &user.Email, &user.Name, &user.CreatedAt, &scope)
	return user, scope, err
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func issue(tx *sql.Tx, userID int64, clientID, resource, scope, family string) (tokenResponse, error) {
	if family == "" {
		family = randomToken()
	}
	result := tokenResponse{randomToken(), "Bearer", int64(AccessLifetime.Seconds()), randomToken(), scope}
	_, err := tx.Exec(`INSERT INTO tokens(access_hash,refresh_hash,family,user_id,client_id,resource,scope,access_expires,refresh_expires) VALUES(?,?,?,?,?,?,?,?,?)`, digest(result.AccessToken), digest(result.RefreshToken), family, userID, clientID, resource, scope, time.Now().Add(AccessLifetime).Unix(), time.Now().Add(RefreshLifetime).Unix())
	return result, err
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 password_hash TEXT NOT NULL, created_at TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
 failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clients (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, auth_method TEXT NOT NULL,
 secret_hash TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_flows (
 id TEXT PRIMARY KEY, csrf_hash TEXT NOT NULL, request_json TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS codes (
 hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), client_id TEXT NOT NULL REFERENCES clients(id),
 redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
 access_hash TEXT PRIMARY KEY, refresh_hash TEXT NOT NULL UNIQUE, family TEXT NOT NULL,
 user_id INTEGER NOT NULL REFERENCES users(id), client_id TEXT NOT NULL REFERENCES clients(id),
 resource TEXT NOT NULL, scope TEXT NOT NULL, access_expires INTEGER NOT NULL, refresh_expires INTEGER NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family);
`

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~", r)) {
			return false
		}
	}
	return true
}
func baseURL(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("public URL must be an HTTPS origin (HTTP allowed on localhost)")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) {
		return "", fmt.Errorf("public URL must use HTTPS, except localhost")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}
func loopback(host string) bool { return host == "localhost" || host == "127.0.0.1" || host == "::1" }
func validRedirect(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Host != "" && u.User == nil && u.Fragment == "" && !strings.ContainsAny(u.Host, ";\"'\\ \t\r\n") && (u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname()))
}

package auth

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

func parseHosting(value string, allowed []string) (string, string, string, []string, error) {
	base, err := baseURL(value)
	if err != nil {
		return "", "", "", nil, err
	}
	u, _ := url.Parse(base)
	origin := u.Scheme + "://" + u.Host
	hosts := []string{}
	for _, item := range allowed {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		check := strings.TrimPrefix(item, "*.")
		if check == "" || strings.ContainsAny(check, "/:?#@ \\;\t\r\n") || strings.Contains(check, "*") || item == "*" {
			return "", "", "", nil, fmt.Errorf("invalid allowed host %q: use a hostname or *.namespace.svc.cluster.local", item)
		}
		hosts = append(hosts, item)
	}
	return base, origin, u.Path, hosts, nil
}
func (s *Server) allowsHost(value string) bool {
	incoming, err := url.Parse("http://" + value)
	if err != nil || incoming.User != nil || incoming.Host != value {
		return false
	}
	expected, _ := url.Parse(s.Origin)
	if strings.EqualFold(value, expected.Host) || loopback(incoming.Hostname()) {
		return true
	}
	host := strings.ToLower(incoming.Hostname())
	for _, allowed := range s.AllowedHosts {
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*")
			if strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".") {
				return true
			}
		} else if host == allowed {
			return true
		}
	}
	return false
}
func cleanBasePath(value string) bool {
	return !strings.ContainsAny(value, "%\\?# \t\r\n") && (value == "" || value == "/" || path.Clean(value) == strings.TrimSuffix(value, "/"))
}

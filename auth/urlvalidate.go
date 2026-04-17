package auth

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// ValidateCallbackURL ensures callback URLs are http(s) and, unless IAM_RELAXED_CALLBACK_URLS
// is set, do not resolve to loopback, private, link-local, or metadata-range addresses.
func ValidateCallbackURL(raw string, name string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%s must use http or https", name)
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}
	if host == "" {
		return fmt.Errorf("%s has invalid host", name)
	}

	relaxed := os.Getenv("IAM_RELAXED_CALLBACK_URLS") != ""

	if ip := net.ParseIP(host); ip != nil {
		return validateIP(ip, relaxed, name)
	}
	if relaxed {
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("%s: could not resolve host: %w", name, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%s: host resolved to no addresses", name)
	}
	for _, ip := range ips {
		if err := validateIP(ip, false, name); err != nil {
			return err
		}
	}
	return nil
}

func validateIP(ip net.IP, relaxed bool, name string) error {
	// Always block cloud / link-local metadata range (SSRF), even in relaxed dev mode.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 {
			return fmt.Errorf("%s must not target metadata range 169.254.0.0/16", name)
		}
	}
	if relaxed {
		return nil
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return fmt.Errorf("%s must not target loopback, private, or link-local addresses (set IAM_RELAXED_CALLBACK_URLS=1 for local dev)", name)
	}
	return nil
}

// Package config contains connection bootstrap and remotely supplied certificate options.
package config

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
)

type Bootstrap struct {
	MasterURL string `json:"master_url"`
	Token     string `json:"token"`
}

func Load(path string) (Bootstrap, error) {
	var c Bootstrap
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return c, err
	}
	if err == nil {
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.DisallowUnknownFields()
		if err = d.Decode(&c); err != nil {
			return c, errors.New("invalid bootstrap JSON")
		}
	}
	if v := os.Getenv("XNODE_MASTER_URL"); v != "" {
		c.MasterURL = v
	}
	if v := os.Getenv("XNODE_TOKEN"); v != "" {
		c.Token = v
	}
	return c, Validate(c)
}
func Validate(c Bootstrap) error {
	u, err := url.Parse(c.MasterURL)
	if err != nil || u.Host == "" || u.Scheme != "wss" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("master_url must be a WSS URL without credentials, query or fragment")
	}
	if strings.TrimSpace(c.Token) == "" || strings.ContainsAny(c.Token, "\r\n") {
		return errors.New("a nonempty token is required")
	}
	return nil
}

// CertConfig is transported inside a remote certificate profile, never bootstrap.
type CertConfig struct {
	AutoTLS               bool              `json:"auto_tls,omitempty"`
	Domain                string            `json:"domain,omitempty"`
	Email                 string            `json:"email,omitempty"`
	CertFile              string            `json:"cert_file,omitempty"`
	KeyFile               string            `json:"key_file,omitempty"`
	CertDir               string            `json:"-"`
	HTTPPort              int               `json:"http_port,omitempty"`
	CertMode              string            `json:"cert_mode"`
	DNSProvider           string            `json:"dns_provider,omitempty"`
	DNSEnv                map[string]string `json:"dns_env,omitempty"`
	CertContent           string            `json:"cert_content,omitempty"`
	KeyContent            string            `json:"key_content,omitempty"`
	PropagationDelay      string            `json:"propagation_delay,omitempty"`
	StartupTimeoutSeconds int               `json:"startup_timeout_seconds,omitempty"`
}

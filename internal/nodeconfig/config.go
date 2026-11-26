// Package nodeconfig renders and validates the config.json consumed by
// ss-server. The panel stores the desired state; the agent writes this form.
package nodeconfig

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	MethodAES128 = "2022-blake3-aes-128-gcm"
	MethodAES256 = "2022-blake3-aes-256-gcm"
	MaxUsers     = 50
	MaxUserIDLen = 64
)

// AnonymousLimits mirrors the optional ss-server anonymous_limits object.
type AnonymousLimits struct {
	MaxTCPPerIP     int `json:"max_tcp_connections_per_ip,omitempty"`
	MaxUDPPerIP     int `json:"max_udp_sessions_per_ip,omitempty"`
	PreauthPerIP    int `json:"preauth_connections_per_ip,omitempty"`
	UploadKBPSPerIP int `json:"upload_kbps_per_ip,omitempty"`
	BurstKB         int `json:"burst_kb,omitempty"`
	IPv6Prefix      int `json:"ipv6_prefix,omitempty"`
	MaxTrackedIPs   int `json:"max_tracked_ips,omitempty"`
}

// Config is the subset of ss-server configuration managed by the panel.
type Config struct {
	Server          string            `json:"server"`
	ServerPort      int               `json:"server_port"`
	Method          string            `json:"method"`
	Password        string            `json:"password"`
	Users           map[string]string `json:"users"`
	Mode            string            `json:"mode,omitempty"`
	RequireIdentity bool              `json:"require_identity,omitempty"`
	ControlSocket   string            `json:"control_socket,omitempty"`
	AccessLog       bool              `json:"access_log,omitempty"`
	AnonymousLimits *AnonymousLimits  `json:"anonymous_limits,omitempty"`
}

// New returns a config with an initialized users map.
func New() Config {
	return Config{
		Server: "0.0.0.0",
		Mode:   "tcp_and_udp",
		Users:  make(map[string]string),
	}
}

// MethodKeyLen returns the PSK length required by a supported method.
func MethodKeyLen(method string) (int, error) {
	switch method {
	case MethodAES128:
		return 16, nil
	case MethodAES256:
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported method %q: use %s or %s", method, MethodAES128, MethodAES256)
	}
}

// GeneratePSK creates a fresh base64 PSK for method.
func GeneratePSK(method string) (string, error) {
	keyLen, err := MethodKeyLen(method)
	if err != nil {
		return "", err
	}
	buf := make([]byte, keyLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate psk: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// ValidatePSK checks that psk is canonical base64 of the method's key length.
func ValidatePSK(method, psk string) error {
	keyLen, err := MethodKeyLen(method)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(psk)
	if err != nil {
		return fmt.Errorf("psk is not valid base64: %w", err)
	}
	if len(raw) != keyLen {
		return fmt.Errorf("psk decodes to %d bytes, method %s needs %d", len(raw), method, keyLen)
	}
	return nil
}

// Validate checks the fields that would make ss-server fail or silently
// ignore a user. It does not require a control socket; the agent does.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server) == "" {
		return errors.New("server is required")
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return fmt.Errorf("server_port %d is out of range", c.ServerPort)
	}
	if err := ValidatePSK(c.Method, c.Password); err != nil {
		return fmt.Errorf("server password: %w", err)
	}
	switch c.Mode {
	case "", "tcp_and_udp", "tcp_only", "udp_only":
	default:
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if len(c.Users) > MaxUsers {
		return fmt.Errorf("too many users: %d (max %d)", len(c.Users), MaxUsers)
	}

	seen := make(map[string]string, len(c.Users))
	for id, psk := range c.Users {
		if id == "" || len(id) > MaxUserIDLen {
			return fmt.Errorf("user id %q must be 1..%d bytes", id, MaxUserIDLen)
		}
		for _, r := range id {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("user id %q contains a control character", id)
			}
		}
		if err := ValidatePSK(c.Method, psk); err != nil {
			return fmt.Errorf("user %q psk: %w", id, err)
		}
		if psk == c.Password {
			return fmt.Errorf("user %q psk equals the server password", id)
		}
		if other, ok := seen[psk]; ok {
			return fmt.Errorf("users %q and %q share a psk", other, id)
		}
		seen[psk] = id
	}
	return nil
}

// Render returns the JSON form written to ss-server's config path.
func (c Config) Render() ([]byte, error) {
	if c.Users == nil {
		c.Users = make(map[string]string)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Load reads and validates a config.json file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Users == nil {
		c.Users = make(map[string]string)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// SortedUserIDs returns user IDs in a stable order for UI and tests.
func (c Config) SortedUserIDs() []string {
	ids := make([]string, 0, len(c.Users))
	for id := range c.Users {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

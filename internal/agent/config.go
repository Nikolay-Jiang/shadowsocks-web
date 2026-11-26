package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config is the on-disk agent configuration.
type Config struct {
	PanelURL        string `json:"panel_url"`
	EnrollmentToken string `json:"enrollment_token"`
	NodeName        string `json:"node_name"`
	DataDir         string `json:"data_dir"`
	ServerBinary    string `json:"server_binary"`
	ServerConfig    string `json:"server_config"`
	ControlSocket   string `json:"control_socket"`
	ApplyMode       string `json:"apply_mode"`
	TLSCA           string `json:"tls_ca,omitempty"`
	SyncWaitSeconds int    `json:"sync_wait_seconds,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.DataDir == "" {
		c.DataDir = "/var/lib/shadowsocks-c/agent"
	}
	if c.ServerBinary == "" {
		c.ServerBinary = "/usr/local/bin/ss-server"
	}
	if c.ServerConfig == "" {
		c.ServerConfig = "/etc/shadowsocks-c/config.json"
	}
	if c.ControlSocket == "" {
		c.ControlSocket = "/run/shadowsocks-c/control.sock"
	}
	if c.ApplyMode == "" {
		c.ApplyMode = "supervisor"
	}
	if c.SyncWaitSeconds <= 0 {
		c.SyncWaitSeconds = 25
	}
	c.PanelURL = strings.TrimRight(c.PanelURL, "/")
}

func (c Config) Validate() error {
	if c.PanelURL == "" {
		return errors.New("panel_url is required")
	}
	u, err := url.Parse(c.PanelURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("panel_url must be an http(s) URL: %q", c.PanelURL)
	}
	if c.NodeName == "" {
		return errors.New("node_name is required")
	}
	if c.ApplyMode != "supervisor" && c.ApplyMode != "systemd" {
		return fmt.Errorf("apply_mode must be supervisor or systemd, got %q", c.ApplyMode)
	}
	if c.ServerBinary == "" || c.ServerConfig == "" || c.ControlSocket == "" || c.DataDir == "" {
		return errors.New("server_binary, server_config, control_socket and data_dir are required")
	}
	return nil
}

func (c Config) statePath() string {
	return filepath.Join(c.DataDir, "state.json")
}

func (c Config) configBackupPath() string {
	return c.ServerConfig + ".last-good"
}

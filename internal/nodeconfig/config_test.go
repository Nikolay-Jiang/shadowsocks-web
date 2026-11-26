package nodeconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	server, err := GeneratePSK(MethodAES256)
	if err != nil {
		t.Fatal(err)
	}
	user, err := GeneratePSK(MethodAES256)
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	c.Server = "127.0.0.1"
	c.ServerPort = 8388
	c.Method = MethodAES256
	c.Password = server
	c.Users["u00001"] = user
	c.RequireIdentity = true
	c.ControlSocket = "/run/shadowsocks-c/control.sock"
	return c
}

func TestGeneratePSK(t *testing.T) {
	for _, method := range []string{MethodAES128, MethodAES256} {
		psk, err := GeneratePSK(method)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidatePSK(method, psk); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
	}
	if _, err := GeneratePSK("aes-256-gcm"); err == nil {
		t.Fatal("expected classic AEAD to be rejected")
	}
}

func TestValidate(t *testing.T) {
	c := validConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Render(); err != nil {
		t.Fatal(err)
	}

	dup := c
	dup.Users = map[string]string{"u00001": c.Users["u00001"], "u00002": c.Users["u00001"]}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "share a psk") {
		t.Fatalf("duplicate psk: %v", err)
	}

	same := c
	same.Users = map[string]string{"u00001": c.Password}
	if err := same.Validate(); err == nil || !strings.Contains(err.Error(), "server password") {
		t.Fatalf("server psk reuse: %v", err)
	}

	bad := c
	bad.Method = "aes-256-gcm"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected classic method to be rejected")
	}

	empty := c
	empty.Users = map[string]string{}
	if err := empty.Validate(); err != nil {
		t.Fatalf("require_identity with no users should be allowed: %v", err)
	}
}

func TestRender(t *testing.T) {
	c := validConfig(t)
	data, err := c.Render()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["users"].(map[string]any)["u00001"] != c.Users["u00001"] {
		t.Fatalf("users missing from rendered config: %s", data)
	}
	if got["require_identity"] != true {
		t.Fatalf("require_identity missing: %s", data)
	}
	if got["mode"] != "tcp_and_udp" {
		t.Fatalf("mode missing: %s", data)
	}
}

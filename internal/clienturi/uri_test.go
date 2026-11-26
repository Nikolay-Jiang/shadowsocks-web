package clienturi

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSSURI(t *testing.T) {
	uri := SSURI("2022-blake3-aes-256-gcm", "server", "user", "2001:db8::1", 8388, "HK 1")
	if !strings.HasPrefix(uri, "ss://") || !strings.Contains(uri, "@[2001:db8::1]:8388#") {
		t.Fatalf("unexpected uri: %s", uri)
	}
	raw := strings.TrimPrefix(strings.SplitN(uri, "@", 2)[0], "ss://")
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "2022-blake3-aes-256-gcm:server:user" {
		t.Fatalf("unexpected userinfo: %s", decoded)
	}
}

// Package clienturi builds SIP002 client links for panel users.
package clienturi

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// SSURI returns ss://BASE64(method:serverPSK:userPSK)@host:port#name.
func SSURI(method, serverPSK, userPSK, host string, port int, name string) string {
	credentials := method + ":" + serverPSK + ":" + userPSK
	encoded := base64.RawURLEncoding.EncodeToString([]byte(credentials))
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if name == "" {
		name = host
	}
	return fmt.Sprintf("ss://%s@%s:%s#%s", encoded, host, strconv.Itoa(port), url.PathEscape(name))
}

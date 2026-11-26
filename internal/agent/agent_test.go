package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/nodeconfig"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

func TestPanelClient(t *testing.T) {
	var gotAuth string
	var syncQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/v1/agent/enroll":
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{NodeID: "nd_1", AgentToken: "at_1"})
		case "/api/v1/agent/sync":
			syncQuery = r.URL.RawQuery
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/report":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewPanelClient(Config{PanelURL: server.URL, SyncWaitSeconds: 1}, "tok")
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := client.Enroll(context.Background(), protocol.EnrollRequest{EnrollmentToken: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.NodeID != "nd_1" || enrolled.AgentToken != "at_1" {
		t.Fatalf("unexpected enrollment: %+v", enrolled)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("authorization header = %q", gotAuth)
	}
	synced, err := client.Sync(context.Background(), 7, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if synced != nil {
		t.Fatal("expected 204 to produce no sync response")
	}
	if !strings.Contains(syncQuery, "revision=7") || !strings.Contains(syncQuery, "wait=2s") {
		t.Fatalf("unexpected sync query: %s", syncQuery)
	}
	if err := client.Report(context.Background(), protocol.AgentReport{Revision: 7, Status: "applied"}); err != nil {
		t.Fatal(err)
	}
}

func TestSendReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	remote := &net.UnixAddr{Name: path, Net: "unixgram"}
	server, err := net.ListenUnixgram("unixgram", remote)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		n, from, err := server.ReadFromUnix(buf)
		if err != nil {
			done <- err
			return
		}
		if string(buf[:n]) != "reload" {
			done <- &net.AddrError{Err: "unexpected command", Addr: string(buf[:n])}
			return
		}
		_, err = server.WriteToUnix([]byte("ok\tadded=1\tremoved=0"), from)
		done <- err
	}()
	text, err := sendReload(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "ok") {
		t.Fatalf("unexpected response: %q", text)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisor(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "server.sh")
	body := "#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sup := NewSupervisor(script, filepath.Join(dir, "config.json"))
	if err := sup.Start(); err != nil {
		t.Fatal(err)
	}
	if !sup.Running() || sup.PID() == 0 {
		t.Fatal("supervisor did not start the child")
	}
	if err := sup.Stop(); err != nil {
		t.Fatal(err)
	}
	if sup.Running() {
		t.Fatal("supervisor still reports a running child")
	}
}

func TestApplyWritesValidConfig(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntrap 'exit 0' TERM\nwhile :; do sleep 1; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	serverPSK, err := nodeconfig.GeneratePSK(nodeconfig.MethodAES256)
	if err != nil {
		t.Fatal(err)
	}
	userPSK, err := nodeconfig.GeneratePSK(nodeconfig.MethodAES256)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	agent := &Agent{
		cfg: Config{
			ServerConfig:  configPath,
			ControlSocket: filepath.Join(dir, "control.sock"),
		},
		sup: NewSupervisor(script, configPath),
	}
	resp := &protocol.SyncResponse{
		Revision: 1,
		Apply:    protocol.ApplyFull,
		Node: protocol.NodeSpec{
			ID:              "nd_1",
			Port:            8388,
			Method:          nodeconfig.MethodAES256,
			ServerPSK:       serverPSK,
			RequireIdentity: true,
		},
		Users: []protocol.UserSpec{{ID: "u00001", PSK: userPSK, Enabled: true}},
	}
	if err := agent.apply(context.Background(), resp); err != nil {
		t.Fatal(err)
	}
	defer agent.sup.Stop()
	got, err := nodeconfig.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Users["u00001"] != userPSK {
		t.Fatalf("user not written: %+v", got.Users)
	}
	if !got.RequireIdentity || got.ServerPort != 8388 {
		t.Fatalf("unexpected config: %+v", got)
	}
}

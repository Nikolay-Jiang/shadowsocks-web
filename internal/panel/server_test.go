package panel

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/nodeconfig"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var tokenPattern = regexp.MustCompile(`(?s)Agent token.*?<code>([0-9a-f]{64})</code>`)

func newTestPanel(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Config{Listen: "127.0.0.1:0", DataDir: dir, PublicURL: "https://panel.example.com", Name: "Test Panel"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, ts, &http.Client{Jar: jar}
}

func getBody(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func postForm(t *testing.T, client *http.Client, url string, values url.Values) (int, string) {
	t.Helper()
	resp, err := client.PostForm(url, values)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func csrf(t *testing.T, html string) string {
	t.Helper()
	m := csrfPattern.FindStringSubmatch(html)
	if len(m) != 2 {
		t.Fatalf("no csrf token in page: %s", html[:min(len(html), 400)])
	}
	return m[1]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestPanelFlow(t *testing.T) {
	s, ts, client := newTestPanel(t)
	defer ts.Close()
	defer s.Close()

	if code, body := getBody(t, client, ts.URL+"/"); code != http.StatusOK || !strings.Contains(body, "Create administrator") {
		t.Fatalf("setup redirect failed: %d %s", code, body)
	}
	if code, body := postForm(t, client, ts.URL+"/setup", url.Values{
		"username": {"admin"}, "password": {"password123"},
	}); code != http.StatusOK || !strings.Contains(body, "Dashboard") || !strings.Contains(body, "Test Panel") {
		t.Fatalf("setup failed: %d %s", code, body)
	}

	_, nodesPage := getBody(t, client, ts.URL+"/nodes")
	formCSRF := csrf(t, nodesPage)
	code, nodeBody := postForm(t, client, ts.URL+"/nodes", url.Values{
		"csrf":             {formCSRF},
		"name":             {"hk-1"},
		"address":          {"127.0.0.1"},
		"port":             {"8388"},
		"method":           {"2022-blake3-aes-256-gcm"},
		"require_identity": {"on"},
	})
	if code != http.StatusOK {
		t.Fatalf("create node: %d %s", code, nodeBody)
	}
	if !strings.Contains(nodeBody, "https://panel.example.com") || !strings.Contains(nodeBody, "Copy config") {
		t.Fatalf("agent config missing public URL or copy button")
	}
	tokenMatch := tokenPattern.FindStringSubmatch(nodeBody)
	if len(tokenMatch) != 2 {
		t.Fatalf("agent token not shown: %s", nodeBody)
	}
	token := tokenMatch[1]

	nodes, err := s.store.ListNodes(t.Context())
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes: %v %+v", err, nodes)
	}
	node := nodes[0]

	enrollBody, _ := json.Marshal(protocol.EnrollRequest{EnrollmentToken: token, NodeName: "hk-1"})
	resp, err := http.Post(ts.URL+"/api/v1/agent/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status: %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent/sync?revision=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	syncResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var first protocol.SyncResponse
	if err := json.NewDecoder(syncResp.Body).Decode(&first); err != nil {
		t.Fatal(err)
	}
	syncResp.Body.Close()
	if first.Apply != protocol.ApplyFull || first.Node.ID != node.ID {
		t.Fatalf("unexpected sync: %+v", first)
	}
	firstReport, _ := json.Marshal(protocol.AgentReport{Revision: first.Revision, Status: "applied"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agent/report", bytes.NewReader(firstReport))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first report status: %d", resp.StatusCode)
	}

	_, usersPage := getBody(t, client, ts.URL+"/users")
	userCSRF := csrf(t, usersPage)
	userPSK, err := nodeconfig.GeneratePSK(node.Method)
	if err != nil {
		t.Fatal(err)
	}
	code, userBody := postForm(t, client, ts.URL+"/users", url.Values{
		"csrf":         {userCSRF},
		"display_name": {"alice"},
		"psk":          {userPSK},
	})
	if code != http.StatusOK || !strings.Contains(userBody, "alice") {
		t.Fatalf("create user: %d %s", code, userBody)
	}
	users, _ := s.store.ListUsers(t.Context())
	if len(users) != 1 {
		t.Fatalf("users: %+v", users)
	}
	user := users[0]

	_, userPage := getBody(t, client, ts.URL+"/users/"+user.ID)
	assignCSRF := csrf(t, userPage)
	code, assignBody := postForm(t, client, ts.URL+"/users/"+user.ID+"/assign", url.Values{
		"csrf":    {assignCSRF},
		"node_id": {node.ID},
	})
	if code != http.StatusOK || !strings.Contains(assignBody, "ss://") {
		t.Fatalf("assign: %d %s", code, assignBody)
	}
	_, nodesHTML := getBody(t, client, ts.URL+"/nodes")
	if !strings.Contains(nodesHTML, "/nodes/"+node.ID+"/users") || !strings.Contains(nodesHTML, "/nodes/"+node.ID+"/logs") {
		t.Fatalf("node actions missing: %s", nodesHTML)
	}
	_, nodeUsersHTML := getBody(t, client, ts.URL+"/nodes/"+node.ID+"/users")
	if !strings.Contains(nodeUsersHTML, user.ID) || !strings.Contains(nodeUsersHTML, "Assigned users") {
		t.Fatalf("node users page: %s", nodeUsersHTML)
	}
	assignment, err := s.store.GetAssignment(t.Context(), node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.PSK != userPSK {
		t.Fatalf("initial PSK was not used: got %q want %q", assignment.PSK, userPSK)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent/sync?revision="+itoa(first.Revision), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	syncResp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var second protocol.SyncResponse
	if err := json.NewDecoder(syncResp.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	syncResp.Body.Close()
	if len(second.Users) != 1 || second.Users[0].ID != user.ID || second.Apply != protocol.ApplyUsers {
		t.Fatalf("unexpected second sync: %+v", second)
	}

	report := protocol.AgentReport{
		Revision: second.Revision,
		Status:   "applied",
		Server:   protocol.ServerStatus{Listening: true},
		Stats: protocol.Stats{
			Users: []protocol.UserStats{{ID: user.ID, Tx: 100, Rx: 200}},
		},
		Logs: []protocol.LogEntry{{Time: time.Now().Unix(), Source: "server", Level: "ERROR", Message: "test node error"}},
	}
	reportBody, _ := json.Marshal(report)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agent/report", bytes.NewReader(reportBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	reportResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	reportResp.Body.Close()
	if reportResp.StatusCode != http.StatusNoContent {
		t.Fatalf("report status: %d", reportResp.StatusCode)
	}
	assignment, err = s.store.GetAssignment(t.Context(), node.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.TotalTx != 100 || assignment.TotalRx != 200 {
		t.Fatalf("traffic not applied: %+v", assignment)
	}
	_, logsHTML := getBody(t, client, ts.URL+"/nodes/"+node.ID+"/logs?level=ERROR")
	if !strings.Contains(logsHTML, "test node error") || !strings.Contains(logsHTML, "ERROR") {
		t.Fatalf("node logs page: %s", logsHTML)
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

func TestPublicURL(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "http://internal:8080/nodes", nil)
	req.Host = "panel.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := s.publicURL(req); got != "https://panel.example.com" {
		t.Fatalf("derived URL = %q", got)
	}
	s.cfg.PublicURL = "https://configured.example.com/"
	if got := s.publicURL(req); got != "https://configured.example.com" {
		t.Fatalf("configured URL = %q", got)
	}
}

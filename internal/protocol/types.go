// Package protocol defines the wire types shared by ss-panel and ss-agent.
package protocol

const (
	APIVersion = "v1"
	Version    = "0.1.0"
)

// Apply mode tells the agent how large the change is.
const (
	ApplyUsers = "users"
	ApplyFull  = "full"
)

// NodeSpec is the server-side part of a managed node. ServerPSK is only sent
// over the agent channel and must never be logged.
type NodeSpec struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Address         string `json:"address"`
	Port            int    `json:"port"`
	Method          string `json:"method"`
	ServerPSK       string `json:"server_psk"`
	RequireIdentity bool   `json:"require_identity"`
	ControlSocket   string `json:"control_socket,omitempty"`
	AccessLog       bool   `json:"access_log"`
}

// UserSpec is one SIP023 identity as the agent should write it.
type UserSpec struct {
	ID      string `json:"id"`
	PSK     string `json:"psk"`
	Enabled bool   `json:"enabled"`
}

// EnrollRequest is sent once with the one-time enrollment token.
type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	NodeName        string `json:"node_name"`
	AgentVersion    string `json:"agent_version"`
	Hostname        string `json:"hostname,omitempty"`
}

// EnrollResponse carries the per-node token. The panel stores only its hash.
type EnrollResponse struct {
	NodeID     string `json:"node_id"`
	AgentToken string `json:"agent_token"`
}

// SyncResponse is the desired state for one node.
type SyncResponse struct {
	Revision        int64      `json:"revision"`
	Apply           string     `json:"apply"`
	Node            NodeSpec   `json:"node"`
	Users           []UserSpec `json:"users"`
	RestartRequired bool       `json:"restart_required"`
}

// AgentReport is the result of applying a revision plus optional stats.
type AgentReport struct {
	Revision int64        `json:"revision"`
	Status   string       `json:"status"` // applied, error, pending
	Error    string       `json:"error,omitempty"`
	Server   ServerStatus `json:"server"`
	Stats    Stats        `json:"stats"`
	Logs     []LogEntry   `json:"logs,omitempty"`
}

// LogEntry is one line captured from ss-server or ss-agent.
type LogEntry struct {
	Time    int64  `json:"ts"`
	Source  string `json:"source"` // server / agent
	Level   string `json:"level"`  // ERROR / WARN / INFO / DEBUG
	Message string `json:"message"`
}

// ServerStatus is the agent's view of the supervised ss-server.
type ServerStatus struct {
	Version   string `json:"version,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Listening bool   `json:"listening"`
}

// Stats mirrors the fields ssctl reports through the control socket.
type Stats struct {
	Global GlobalStats `json:"global"`
	Users  []UserStats `json:"users"`
}

type GlobalStats struct {
	Tx          uint64 `json:"tx"`
	Rx          uint64 `json:"rx"`
	TcpLive     uint32 `json:"tcp_live"`
	TcpRefused  uint64 `json:"tcp_refused"`
	UdpSessions uint32 `json:"udp_sessions"`
	TrackedIPs  uint32 `json:"tracked_ips"`
	Users       uint32 `json:"users"`
}

type UserStats struct {
	ID       string `json:"id"`
	TCP      uint32 `json:"tcp"`
	UDP      uint32 `json:"udp"`
	Tx       uint64 `json:"tx"`
	Rx       uint64 `json:"rx"`
	LastSeen uint64 `json:"last_seen"`
}

// ErrorResponse is used by both HTTP APIs for a machine-readable failure.
type ErrorResponse struct {
	Error string `json:"error"`
}

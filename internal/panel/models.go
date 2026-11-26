package panel

type Node struct {
	ID              string
	Name            string
	Address         string
	Port            int
	Method          string
	ServerPSK       string
	RequireIdentity bool
	AccessLog       bool
	ApplyMode       string
	AgentVersion    string
	LastSeen        int64
	Status          string
	Revision        int64
	AppliedRevision int64
	PendingFull     bool
	LastError       string
	Tx              uint64
	Rx              uint64
	TcpLive         uint32
	UdpSessions     uint32
	TrackedIPs      uint32
	CreatedAt       int64
	UpdatedAt       int64
}

type User struct {
	ID          string
	DisplayName string
	Enabled     bool
	QuotaBytes  int64
	ExpiresAt   int64
	Note        string
	// DefaultPSK is only used while creating a user. GetUser/ListUsers do
	// not load it; read it with UserDefaultPSK when assigning a node.
	DefaultPSK string
	CreatedAt  int64
	UpdatedAt  int64
}

type Assignment struct {
	NodeID     string
	UserID     string
	PSK        string
	Enabled    bool
	TotalTx    uint64
	TotalRx    uint64
	LastRawTx  uint64
	LastRawRx  uint64
	BaselineTx uint64
	BaselineRx uint64
	LastSeen   int64
}

type AuditEntry struct {
	ID         int64
	TS         int64
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Detail     string
	RemoteIP   string
}

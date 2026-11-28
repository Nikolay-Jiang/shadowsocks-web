package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/clienturi"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/nodeconfig"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

type dashboardView struct {
	Nodes       []Node
	Users       []User
	Audit       []AuditEntry
	OnlineNodes int
}

type nodesView struct {
	Nodes []Node
}

type nodeView struct {
	Node        Node
	Assignments []Assignment
	Users       []User
	UserNames   map[string]string
	Token       string
}

type usersView struct {
	Users []User
}

type assignmentView struct {
	Assignment
	Node Node
	URI  string
}

type userView struct {
	User          User
	Nodes         []Node
	Assignments   []assignmentView
	TotalTx       uint64
	TotalRx       uint64
	HasDefaultPSK bool
}

type nodeUserRow struct {
	User       User
	Assignment Assignment
}

type nodeUsersView struct {
	Node           Node
	Assignments    []nodeUserRow
	AvailableUsers []User
}

type nodeLogsView struct {
	Node  Node
	Logs  []protocol.LogEntry
	Level string
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit, _ := s.store.ListAudit(r.Context(), 20)
	online := 0
	for _, n := range nodes {
		if n.Status == "online" {
			online++
		}
	}
	s.pageFor(w, r, "dashboard", pageData{Title: "Dashboard", Data: dashboardView{Nodes: nodes, Users: users, Audit: audit, OnlineNodes: online}})
}

func (s *Server) nodesPage(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.pageFor(w, r, "nodes", pageData{Title: "Nodes", Data: nodesView{Nodes: nodes}})
}

func (s *Server) nodeCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	node := Node{
		Name:            strings.TrimSpace(r.FormValue("name")),
		Address:         strings.TrimSpace(r.FormValue("address")),
		Port:            atoiDefault(r.FormValue("port"), 8388),
		Method:          r.FormValue("method"),
		ServerPSK:       strings.TrimSpace(r.FormValue("server_psk")),
		RequireIdentity: formBool(r, "require_identity"),
		AccessLog:       formBool(r, "access_log"),
		ApplyMode:       "supervisor",
	}
	if node.Method == "" {
		node.Method = nodeconfig.MethodAES256
	}
	if node.ServerPSK == "" {
		psk, err := nodeconfig.GeneratePSK(node.Method)
		if err != nil {
			s.nodeFormError(w, r, "Create node", err)
			return
		}
		node.ServerPSK = psk
	}
	if err := validateNodeSettings(node); err != nil {
		s.nodeFormError(w, r, "Create node", err)
		return
	}
	token := randomToken(32)
	created, err := s.store.CreateNode(r.Context(), node, token)
	if err != nil {
		s.nodeFormError(w, r, "Create node", err)
		return
	}
	sess := sessionFrom(r)
	s.audit(r, sess, "create", "node", created.ID, created.Name)
	s.showNode(w, r, created, token)
}

func (s *Server) nodePage(w http.ResponseWriter, r *http.Request) {
	node, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.showNode(w, r, node, "")
}

func (s *Server) nodeUsersPage(w http.ResponseWriter, r *http.Request) {
	node, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	assignments, err := s.store.ListAssignmentsForNode(r.Context(), node.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	byID := make(map[string]User, len(users))
	for _, u := range users {
		byID[u.ID] = u
	}
	assigned := make(map[string]bool, len(assignments))
	var rows []nodeUserRow
	for _, a := range assignments {
		assigned[a.UserID] = true
		if u, ok := byID[a.UserID]; ok {
			rows = append(rows, nodeUserRow{User: u, Assignment: a})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].User.ID < rows[j].User.ID })
	var available []User
	for _, u := range users {
		if !assigned[u.ID] {
			available = append(available, u)
		}
	}
	sort.Slice(available, func(i, j int) bool { return available[i].ID < available[j].ID })
	s.pageFor(w, r, "node_users", pageData{Title: node.Name + " users", Data: nodeUsersView{
		Node: node, Assignments: rows, AvailableUsers: available,
	}})
}

func (s *Server) nodeAssignUser(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	node, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	user, err := s.store.GetUser(r.Context(), r.FormValue("user_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.assignUserToNode(r.Context(), node, user, strings.TrimSpace(r.FormValue("psk"))); err != nil {
		s.pageFor(w, r, "node_users", pageData{Title: node.Name + " users", Error: fmt.Sprintf("assign: %v", err), Data: nodeUsersView{Node: node}})
		return
	}
	s.audit(r, sessionFrom(r), "assign", "node", node.ID, user.ID)
	redirect(w, r, "/nodes/"+node.ID+"/users")
}

func (s *Server) nodeUnassignUser(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	node, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	userID := r.FormValue("user_id")
	if err := s.store.RemoveAssignment(r.Context(), node.ID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.store.IncrementNodeRevision(r.Context(), node.ID)
	s.audit(r, sessionFrom(r), "unassign", "node", node.ID, userID)
	redirect(w, r, "/nodes/"+node.ID+"/users")
}

func (s *Server) nodeLogsPage(w http.ResponseWriter, r *http.Request) {
	node, err := s.store.GetNode(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	level := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level")))
	logs, err := s.store.ListNodeLogs(r.Context(), node.ID, level, 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.pageFor(w, r, "node_logs", pageData{Title: node.Name + " logs", Data: nodeLogsView{Node: node, Logs: logs, Level: level}})
}

func (s *Server) nodeFormError(w http.ResponseWriter, r *http.Request, title string, err error) {
	s.pageFor(w, r, "nodes", pageData{Title: title, Error: err.Error(), Data: nodesView{}})
}

func (s *Server) showNode(w http.ResponseWriter, r *http.Request, node Node, token string) {
	assignments, err := s.store.ListAssignmentsForNode(r.Context(), node.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	userNames := make(map[string]string, len(users))
	for _, u := range users {
		userNames[u.ID] = u.DisplayName
	}
	s.pageFor(w, r, "node", pageData{Title: node.Name, Data: nodeView{
		Node: node, Assignments: assignments, Users: users, UserNames: userNames, Token: token,
	}})
}

func (s *Server) nodeUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	node.Name = strings.TrimSpace(r.FormValue("name"))
	node.Address = strings.TrimSpace(r.FormValue("address"))
	node.Port = atoiDefault(r.FormValue("port"), node.Port)
	node.Method = r.FormValue("method")
	node.RequireIdentity = formBool(r, "require_identity")
	node.AccessLog = formBool(r, "access_log")
	if psk := strings.TrimSpace(r.FormValue("server_psk")); psk != "" {
		node.ServerPSK = psk
	}
	if err := validateNodeSettings(node); err != nil {
		s.pageFor(w, r, "node", pageData{Title: node.Name, Error: err.Error(), Data: nodeView{Node: node}})
		return
	}
	if err := s.store.UpdateNode(r.Context(), node); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r, sessionFrom(r), "update", "node", node.ID, node.Name)
	redirect(w, r, "/nodes/"+id)
}

func (s *Server) nodeDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = s.store.DeleteNode(r.Context(), id)
	s.audit(r, sessionFrom(r), "delete", "node", id, "")
	redirect(w, r, "/nodes")
}

func (s *Server) nodeRotateToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token := randomToken(32)
	if err := s.store.RotateNodeToken(r.Context(), id, token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	node, err := s.store.GetNode(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.audit(r, sessionFrom(r), "rotate-token", "node", id, "")
	s.showNode(w, r, node, token)
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.pageFor(w, r, "users", pageData{Title: "Users", Data: usersView{Users: users}})
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("display_name"))
	if name == "" {
		name = "user"
	}
	psk := strings.TrimSpace(r.FormValue("psk"))
	if psk != "" {
		if err := nodeconfig.ValidatePortablePSK(psk); err != nil {
			s.usersError(w, r, "Create user", err)
			return
		}
	}
	user, err := s.store.CreateUser(r.Context(), User{DisplayName: name, Enabled: true, DefaultPSK: psk})
	if err != nil {
		s.usersError(w, r, "Create user", err)
		return
	}
	s.audit(r, sessionFrom(r), "create", "user", user.ID, user.DisplayName)
	redirect(w, r, "/users/"+user.ID)
}

func (s *Server) userPage(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.showUser(w, r, user, "")
}

func (s *Server) showUser(w http.ResponseWriter, r *http.Request, user User, message string) {
	s.renderUser(w, r, user, message, "")
}

func (s *Server) renderUser(w http.ResponseWriter, r *http.Request, user User, flash, errorText string) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	assignments, err := s.store.ListAssignmentsForUser(r.Context(), user.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nodeByID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	var views []assignmentView
	var totalTx, totalRx uint64
	for _, a := range assignments {
		n, ok := nodeByID[a.NodeID]
		if !ok {
			continue
		}
		views = append(views, assignmentView{
			Assignment: a,
			Node:       n,
			URI:        clienturi.SSURI(n.Method, n.ServerPSK, a.PSK, n.Address, n.Port, user.DisplayName),
		})
		totalTx += a.TotalTx
		totalRx += a.TotalRx
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Node.Name < views[j].Node.Name })
	defaultPSK, _ := s.store.UserDefaultPSK(r.Context(), user.ID)
	s.pageFor(w, r, "user", pageData{Title: user.DisplayName, Data: userView{
		User: user, Nodes: nodes, Assignments: views, TotalTx: totalTx, TotalRx: totalRx,
		HasDefaultPSK: defaultPSK != "",
	}, Flash: flash, Error: errorText})
}

func (s *Server) usersError(w http.ResponseWriter, r *http.Request, title string, err error) {
	users, _ := s.store.ListUsers(r.Context())
	s.pageFor(w, r, "users", pageData{Title: title, Error: err.Error(), Data: usersView{Users: users}})
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = r.ParseForm()
	beforeEnabled := user.Enabled
	user.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
	if user.DisplayName == "" {
		user.DisplayName = user.ID
	}
	user.Enabled = formBool(r, "enabled")
	user.Note = strings.TrimSpace(r.FormValue("note"))
	if quota := strings.TrimSpace(r.FormValue("quota_bytes")); quota != "" {
		v, err := strconv.ParseInt(quota, 10, 64)
		if err != nil || v < 0 {
			s.pageFor(w, r, "user", pageData{Title: user.DisplayName, Error: "quota must be a non-negative integer", Data: userView{User: user}})
			return
		}
		user.QuotaBytes = v
	} else {
		user.QuotaBytes = 0
	}
	user.ExpiresAt = 0
	if expiry := strings.TrimSpace(r.FormValue("expires_at")); expiry != "" {
		t, err := time.Parse("2006-01-02", expiry)
		if err != nil {
			s.pageFor(w, r, "user", pageData{Title: user.DisplayName, Error: "expires_at must be YYYY-MM-DD", Data: userView{User: user}})
			return
		}
		user.ExpiresAt = t.Add(24 * time.Hour).Unix()
	}
	if err := s.store.UpdateUser(r.Context(), user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if beforeEnabled != user.Enabled {
		s.incrementUserNodes(r.Context(), id)
	}
	s.audit(r, sessionFrom(r), "update", "user", id, user.DisplayName)
	redirect(w, r, "/users/"+id)
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	nodes, _ := s.store.AssignedNodeIDs(r.Context(), id)
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, nodeID := range nodes {
		_ = s.store.IncrementNodeRevision(r.Context(), nodeID)
	}
	s.audit(r, sessionFrom(r), "delete", "user", id, "")
	redirect(w, r, "/users")
}

func (s *Server) userAssign(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userID := r.PathValue("id")
	nodeID := r.FormValue("node_id")
	node, err := s.store.GetNode(r.Context(), nodeID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.assignUserToNode(r.Context(), node, user, strings.TrimSpace(r.FormValue("psk"))); err != nil {
		s.renderUser(w, r, user, "", fmt.Sprintf("assign: %v", err))
		return
	}
	s.audit(r, sessionFrom(r), "assign", "user", userID, nodeID)
	redirect(w, r, "/users/"+userID)
}

func (s *Server) assignUserToNode(ctx context.Context, node Node, user User, psk string) error {
	if psk == "" {
		var err error
		psk, err = s.store.UserDefaultPSK(ctx, user.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if psk != "" {
		if err := validateAssignmentPSK(node, psk); err != nil {
			return err
		}
		if err := s.store.AssignUser(ctx, node.ID, user.ID, psk); err != nil {
			return err
		}
		return s.store.IncrementNodeRevision(ctx, node.ID)
	}
	var lastErr error
	for i := 0; i < 5; i++ {
		generated, err := nodeconfig.GeneratePSK(node.Method)
		if err != nil {
			return err
		}
		lastErr = s.store.AssignUser(ctx, node.ID, user.ID, generated)
		if lastErr == nil {
			return s.store.IncrementNodeRevision(ctx, node.ID)
		}
	}
	return lastErr
}

func validateAssignmentPSK(node Node, psk string) error {
	if psk == node.ServerPSK {
		return errors.New("user PSK must not equal the node server PSK")
	}
	return nodeconfig.ValidatePSK(node.Method, psk)
}

func (s *Server) userUnassign(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userID := r.PathValue("id")
	nodeID := r.FormValue("node_id")
	if err := s.store.RemoveAssignment(r.Context(), nodeID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.store.IncrementNodeRevision(r.Context(), nodeID)
	s.audit(r, sessionFrom(r), "unassign", "user", userID, nodeID)
	redirect(w, r, "/users/"+userID)
}

func (s *Server) incrementUserNodes(ctx context.Context, userID string) {
	nodes, _ := s.store.AssignedNodeIDs(ctx, userID)
	for _, id := range nodes {
		_ = s.store.IncrementNodeRevision(ctx, id)
	}
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAudit(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.pageFor(w, r, "audit", pageData{Title: "Audit", Data: entries})
}

func validateNodeSettings(node Node) error {
	c := nodeconfig.Config{
		Server:     node.Address,
		ServerPort: node.Port,
		Method:     node.Method,
		Password:   node.ServerPSK,
		Users:      map[string]string{},
		Mode:       "tcp_and_udp",
	}
	if err := c.Validate(); err != nil {
		return err
	}
	return nil
}

func atoiDefault(value string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return v
}

func isNoRows(err error) bool { return err == sql.ErrNoRows }

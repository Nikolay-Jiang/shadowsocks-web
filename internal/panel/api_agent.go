package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) agentNode(r *http.Request) (Node, error) {
	header := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" || token == header {
		return Node{}, errors.New("missing bearer token")
	}
	return s.store.FindNodeByToken(r.Context(), token)
}

func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "invalid json"})
		return
	}
	if req.EnrollmentToken == "" {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: "invalid enrollment token"})
		return
	}
	node, err := s.store.FindNodeByToken(r.Context(), req.EnrollmentToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: "invalid enrollment token"})
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{NodeID: node.ID, AgentToken: req.EnrollmentToken})
}

func (s *Server) agentSync(w http.ResponseWriter, r *http.Request) {
	node, err := s.agentNode(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: "invalid agent token"})
		return
	}
	revision, _ := strconv.ParseInt(r.URL.Query().Get("revision"), 10, 64)
	wait, _ := time.ParseDuration(r.URL.Query().Get("wait"))
	if wait > 30*time.Second {
		wait = 30 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		node, err = s.store.GetNode(r.Context(), node.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: "node unavailable"})
			return
		}
		if node.Revision > revision || time.Now().After(deadline) {
			break
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	users, err := s.store.NodeUsers(r.Context(), node.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: "users unavailable"})
		return
	}
	apply := protocol.ApplyUsers
	if node.PendingFull || revision == 0 {
		apply = protocol.ApplyFull
	}
	resp := protocol.SyncResponse{
		Revision: node.Revision,
		Apply:    apply,
		Node: protocol.NodeSpec{
			ID:              node.ID,
			Name:            node.Name,
			Address:         node.Address,
			Port:            node.Port,
			Method:          node.Method,
			ServerPSK:       node.ServerPSK,
			RequireIdentity: node.RequireIdentity,
			AccessLog:       node.AccessLog,
		},
		Users:           users,
		RestartRequired: node.PendingFull,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	node, err := s.agentNode(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, protocol.ErrorResponse{Error: "invalid agent token"})
		return
	}
	var report protocol.AgentReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		writeJSON(w, http.StatusBadRequest, protocol.ErrorResponse{Error: "invalid json"})
		return
	}
	status := "online"
	if report.Status == "error" {
		status = "error"
	} else if report.Status != "applied" && report.Status != "" {
		status = "degraded"
	}
	if err := s.store.SetNodeReport(r.Context(), node.ID, report.Revision, status, report.Error, report.Server.Version); err != nil {
		writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: "store report"})
		return
	}
	if err := s.store.ApplyStats(r.Context(), node.ID, report); err != nil {
		writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: "store stats"})
		return
	}
	if err := s.store.AppendLogs(r.Context(), node.ID, report.Logs); err != nil {
		writeJSON(w, http.StatusInternalServerError, protocol.ErrorResponse{Error: "store logs"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

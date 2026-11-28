package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/nodeconfig"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

const (
	reportInterval = 10 * time.Second
	retryDelay     = 5 * time.Second
)

// Agent reconciles one node with the panel.
type Agent struct {
	cfg      Config
	client   *PanelClient
	sup      *Supervisor
	logs     *LogBuffer
	agentLog *logLineWriter

	mu       sync.Mutex
	state    state
	version  string
	status   string
	lastErr  string
	reportMu sync.Mutex
}

func New(cfg Config) (*Agent, error) {
	if cfg.ApplyMode != "supervisor" {
		return nil, fmt.Errorf("apply_mode %q is not implemented; use supervisor", cfg.ApplyMode)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data_dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ServerConfig), 0o755); err != nil {
		return nil, fmt.Errorf("create server config dir: %w", err)
	}
	if _, err := os.Stat(cfg.ServerBinary); err != nil {
		return nil, fmt.Errorf("server_binary: %w", err)
	}
	st, err := loadState(cfg.statePath())
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	client, err := NewPanelClient(cfg, st.AgentToken)
	if err != nil {
		return nil, err
	}
	logs := NewLogBuffer(logBufferEntries)
	return &Agent{
		cfg:      cfg,
		client:   client,
		sup:      NewSupervisor(cfg.ServerBinary, cfg.ServerConfig, newLogLineWriter("server", logs)),
		logs:     logs,
		agentLog: newLogLineWriter("agent", logs),
		state:    st,
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	defer a.sup.Stop()
	if a.agentLog != nil {
		previous := log.Writer()
		log.SetOutput(io.MultiWriter(os.Stderr, a.agentLog))
		defer log.SetOutput(previous)
	}
	a.version = serverVersion(a.cfg.ServerBinary)
	if _, err := os.Stat(a.cfg.ServerConfig); err == nil {
		if err := a.sup.Start(); err != nil {
			log.Printf("initial ss-server start: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		a.syncLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		a.reportLoop(ctx)
	}()
	wg.Wait()
	return nil
}

func (a *Agent) syncLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := a.ensureEnrolled(ctx); err != nil {
			log.Printf("enroll: %v", err)
			if !sleep(ctx, retryDelay) {
				return
			}
			continue
		}
		a.ensureServer()

		a.mu.Lock()
		revision := a.state.Revision
		a.mu.Unlock()
		wait := time.Duration(a.cfg.SyncWaitSeconds) * time.Second
		resp, err := a.client.Sync(ctx, revision, wait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("sync: %v", err)
			if !sleep(ctx, retryDelay) {
				return
			}
			continue
		}
		if resp == nil {
			continue
		}
		if err := a.apply(ctx, resp); err != nil {
			log.Printf("apply revision %d: %v", resp.Revision, err)
			a.setStatus("error", err.Error())
			a.report(ctx, resp.Revision, "error", err.Error())
			if !sleep(ctx, retryDelay) {
				return
			}
			continue
		}
		a.mu.Lock()
		a.state.Revision = resp.Revision
		a.status = "applied"
		a.lastErr = ""
		err = saveState(a.cfg.statePath(), a.state)
		a.mu.Unlock()
		if err != nil {
			log.Printf("save state: %v", err)
		}
		a.report(ctx, resp.Revision, "applied", "")
	}
}

func (a *Agent) reportLoop(ctx context.Context) {
	ticker := time.NewTicker(reportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.mu.Lock()
			token := a.state.AgentToken
			revision := a.state.Revision
			status := a.status
			message := a.lastErr
			a.mu.Unlock()
			if token == "" {
				continue
			}
			if status == "" {
				status = "applied"
			}
			a.report(ctx, revision, status, message)
		}
	}
}

func (a *Agent) ensureEnrolled(ctx context.Context) error {
	a.mu.Lock()
	st := a.state
	a.mu.Unlock()
	if st.NodeID != "" && st.AgentToken != "" {
		return nil
	}
	hostname, _ := os.Hostname()
	req := protocol.EnrollRequest{
		EnrollmentToken: a.cfg.EnrollmentToken,
		NodeName:        a.cfg.NodeName,
		AgentVersion:    protocol.Version,
		Hostname:        hostname,
	}
	resp, err := a.client.Enroll(ctx, req)
	if err != nil {
		return err
	}
	if resp.NodeID == "" || resp.AgentToken == "" {
		return errors.New("panel returned an incomplete enrollment")
	}
	a.mu.Lock()
	a.state.NodeID = resp.NodeID
	a.state.AgentToken = resp.AgentToken
	st = a.state
	a.mu.Unlock()
	a.client.SetToken(resp.AgentToken)
	return saveState(a.cfg.statePath(), st)
}

func (a *Agent) ensureServer() {
	if a.sup.Running() {
		return
	}
	if _, err := os.Stat(a.cfg.ServerConfig); err != nil {
		return
	}
	if err := a.sup.Start(); err != nil {
		log.Printf("start ss-server: %v", err)
	}
}

func (a *Agent) apply(ctx context.Context, resp *protocol.SyncResponse) error {
	cfg := nodeconfig.New()
	cfg.Server = "0.0.0.0"
	cfg.ServerPort = resp.Node.Port
	cfg.Method = resp.Node.Method
	cfg.Password = resp.Node.ServerPSK
	cfg.RequireIdentity = resp.Node.RequireIdentity
	cfg.ControlSocket = resp.Node.ControlSocket
	if cfg.ControlSocket == "" {
		cfg.ControlSocket = a.cfg.ControlSocket
	}
	cfg.AccessLog = resp.Node.AccessLog
	cfg.Mode = "tcp_and_udp"
	for _, user := range resp.Users {
		if user.Enabled {
			cfg.Users[user.ID] = user.PSK
		}
	}
	data, err := cfg.Render()
	if err != nil {
		return fmt.Errorf("render config: %w", err)
	}

	old, oldErr := os.ReadFile(a.cfg.ServerConfig)
	if oldErr == nil {
		if err := writeFileAtomic(a.cfg.configBackupPath(), old, 0o600); err != nil {
			log.Printf("save last-good config: %v", err)
		}
	}
	if err := writeFileAtomic(a.cfg.ServerConfig, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	reload := resp.Apply == protocol.ApplyUsers && a.sup.Running()
	if reload {
		text, err := sendReload(a.cfg.ControlSocket)
		if err == nil && strings.HasPrefix(text, "ok") {
			return nil
		}
		if err == nil && strings.Contains(text, "restart_required") {
			reload = false
		} else {
			a.restore(old, oldErr)
			_ = a.sup.Restart()
			if err != nil {
				return fmt.Errorf("reload: %w", err)
			}
			return fmt.Errorf("reload rejected: %s", strings.TrimSpace(text))
		}
	}
	if err := a.sup.Restart(); err != nil {
		a.restore(old, oldErr)
		_ = a.sup.Restart()
		return fmt.Errorf("restart ss-server: %w", err)
	}
	return nil
}

func (a *Agent) restore(old []byte, oldErr error) {
	if oldErr != nil {
		return
	}
	if err := writeFileAtomic(a.cfg.ServerConfig, old, 0o600); err != nil {
		log.Printf("restore config: %v", err)
	}
}

func (a *Agent) setStatus(status, message string) {
	a.mu.Lock()
	a.status = status
	a.lastErr = message
	a.mu.Unlock()
}

func (a *Agent) report(ctx context.Context, revision int64, status, message string) {
	a.reportMu.Lock()
	defer a.reportMu.Unlock()
	report := protocol.AgentReport{
		Revision: revision,
		Status:   status,
		Error:    message,
		Server: protocol.ServerStatus{
			Version:   a.version,
			PID:       a.sup.PID(),
			Listening: a.sup.Running() && socketExists(a.cfg.ControlSocket),
		},
	}
	if stats, err := a.collectStats(); err == nil {
		report.Stats = stats
	}
	var batch []protocol.LogEntry
	if a.logs != nil {
		batch = a.logs.Snapshot(logBatchMax)
		report.Logs = batch
	}
	reportCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := a.client.Report(reportCtx, report); err != nil {
		if ctx.Err() == nil {
			log.Printf("report: %v", err)
		}
		return
	}
	if a.logs != nil && len(batch) != 0 {
		a.logs.Drop(len(batch))
	}
}

func (a *Agent) collectStats() (protocol.Stats, error) {
	var stats protocol.Stats
	usersRaw, err := controlQuery(a.cfg.ControlSocket, "users")
	if err != nil {
		return stats, err
	}
	var users struct {
		Users []protocol.UserStats `json:"users"`
	}
	if err := json.Unmarshal(usersRaw, &users); err != nil {
		return stats, fmt.Errorf("parse users: %w", err)
	}
	stats.Users = users.Users
	globalRaw, err := controlQuery(a.cfg.ControlSocket, "stats")
	if err != nil {
		return stats, err
	}
	if err := json.Unmarshal(globalRaw, &stats.Global); err != nil {
		return stats, fmt.Errorf("parse stats: %w", err)
	}
	return stats, nil
}

func socketExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

func serverVersion(binary string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

package agent

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Supervisor runs ss-server as a child. The agent owns the process so it can
// reload or restart it without needing systemd privileges.
type Supervisor struct {
	binary string
	config string
	sink   io.Writer

	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
}

func NewSupervisor(binary, config string, sinks ...io.Writer) *Supervisor {
	var sink io.Writer
	if len(sinks) != 0 {
		sink = sinks[0]
	}
	return &Supervisor{binary: binary, config: config, sink: sink}
}

func (s *Supervisor) Start() error {
	s.mu.Lock()
	if s.cmd != nil {
		s.mu.Unlock()
		return nil
	}
	cmd := exec.Command(s.binary, "-c", s.config)
	if s.sink != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, s.sink)
		cmd.Stderr = io.MultiWriter(os.Stderr, s.sink)
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("start ss-server: %w", err)
	}
	done := make(chan struct{})
	s.cmd = cmd
	s.done = done
	s.mu.Unlock()

	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("ss-server exited: %v", err)
		}
		close(done)
		s.mu.Lock()
		if s.cmd == cmd {
			s.cmd = nil
			s.done = nil
		}
		s.mu.Unlock()
	}()
	return nil
}

func (s *Supervisor) Stop() error {
	s.mu.Lock()
	cmd := s.cmd
	done := s.done
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
		return fmt.Errorf("ss-server did not stop within 5s")
	}
}

func (s *Supervisor) Restart() error {
	if err := s.Stop(); err != nil {
		log.Printf("stop before restart: %v", err)
	}
	return s.Start()
}

func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmd != nil
}

func (s *Supervisor) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil || s.cmd.Process == nil {
		return 0
	}
	return s.cmd.Process.Pid
}

package agent

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

var controlSeq atomic.Uint64

// roundTrip sends one datagram to ss-server's local control socket. The
// caller must bind a local path, otherwise a Unix datagram cannot reply.
func roundTrip(socketPath, command string, timeout time.Duration) (string, error) {
	if socketPath == "" {
		return "", fmt.Errorf("control socket path is empty")
	}
	local := filepath.Join(os.TempDir(), fmt.Sprintf("ss-agent-%d-%d.sock", os.Getpid(), controlSeq.Add(1)))
	_ = os.Remove(local)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: local, Net: "unixgram"})
	if err != nil {
		return "", fmt.Errorf("bind control client: %w", err)
	}
	defer func() {
		_ = conn.Close()
		_ = os.Remove(local)
	}()

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	remote := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	if _, err := conn.WriteToUnix([]byte(command), remote); err != nil {
		return "", fmt.Errorf("send control request: %w", err)
	}
	buf := make([]byte, 65500)
	n, _, err := conn.ReadFromUnix(buf)
	if err != nil {
		return "", fmt.Errorf("read control response: %w", err)
	}
	return string(buf[:n]), nil
}

func sendReload(socketPath string) (string, error) {
	return roundTrip(socketPath, "reload", 5*time.Second)
}

func controlQuery(socketPath, command string) ([]byte, error) {
	text, err := roundTrip(socketPath, command+" json", 3*time.Second)
	if err != nil {
		return nil, err
	}
	return []byte(text), nil
}

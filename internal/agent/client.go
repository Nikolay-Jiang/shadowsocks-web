package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

type PanelClient struct {
	base string
	http *http.Client

	mu    sync.RWMutex
	token string
}

func NewPanelClient(cfg Config, token string) (*PanelClient, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSCA != "" {
		pem, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("read tls_ca: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca %s contains no certificates", cfg.TLSCA)
		}
		tlsConfig.RootCAs = pool
	}
	return &PanelClient{
		base:  cfg.PanelURL,
		token: token,
		http: &http.Client{
			Timeout: time.Duration(cfg.SyncWaitSeconds+15) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

func (c *PanelClient) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.mu.RLock()
	token := c.token
	c.mu.RUnlock()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, fmt.Errorf("panel %s: %s: %s", path, resp.Status, string(msg))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

func (c *PanelClient) SetToken(token string) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
}

func (c *PanelClient) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	_, err := c.do(ctx, http.MethodPost, "/api/"+protocol.APIVersion+"/agent/enroll", req, &out)
	return out, err
}

func (c *PanelClient) Sync(ctx context.Context, revision int64, wait time.Duration) (*protocol.SyncResponse, error) {
	query := url.Values{}
	query.Set("revision", strconv.FormatInt(revision, 10))
	if wait > 0 {
		query.Set("wait", wait.String())
	}
	var out protocol.SyncResponse
	status, err := c.do(ctx, http.MethodGet, "/api/"+protocol.APIVersion+"/agent/sync?"+query.Encode(), nil, &out)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &out, nil
}

func (c *PanelClient) Report(ctx context.Context, report protocol.AgentReport) error {
	_, err := c.do(ctx, http.MethodPost, "/api/"+protocol.APIVersion+"/agent/report", report, nil)
	return err
}

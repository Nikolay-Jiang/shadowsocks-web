package panel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Crypt encrypts PSKs at rest. The key comes from SS_PANEL_MASTER_KEY
// (base64, 32 bytes) or, for a self-contained install, data/master.key.
type Crypt struct {
	aead cipher.AEAD
}

func OpenCrypt(dataDir string) (*Crypt, error) {
	var key []byte
	if encoded := os.Getenv("SS_PANEL_MASTER_KEY"); encoded != "" {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("SS_PANEL_MASTER_KEY: %w", err)
		}
		if len(raw) != 32 {
			return nil, errors.New("SS_PANEL_MASTER_KEY must decode to 32 bytes")
		}
		key = raw
	} else {
		path := filepath.Join(dataDir, "master.key")
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			raw = make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return nil, err
			}
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return nil, err
			}
			if err := writeFileAtomic(path, raw, 0o600); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("%s must contain 32 bytes", path)
		}
		key = raw
	}
	return newCrypt(key)
}

func newCrypt(key []byte) (*Crypt, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Crypt{aead: aead}, nil
}

func (c *Crypt) Encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plain, nil), nil
}

func (c *Crypt) Decrypt(sealed []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("encrypted value is too short")
	}
	return c.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

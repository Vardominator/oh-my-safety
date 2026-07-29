package controller

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const bootstrapTokenBytes = 32

// BootstrapResult contains the one-time administrator bearer token and the
// public policy-verification key. The token is returned only to the local
// bootstrap caller; the config file stores its SHA-256 digest.
type BootstrapResult struct {
	Schema           string `json:"schema"`
	SchemaVersion    int    `json:"schema_version"`
	AdminID          string `json:"admin_id"`
	AdminToken       string `json:"admin_token"`
	SigningPublicKey string `json:"signing_public_key"`
}

// InitializeAdminConfig creates the initial mode-600 administrator config.
// It refuses to replace an existing path.
func InitializeAdminConfig(path, administratorID string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("admin config path is required")
	}
	if !validIdentifier(administratorID) {
		return "", errors.New("administrator id is invalid")
	}
	if err := ensureNewPrivateParent(filepath.Dir(path)); err != nil {
		return "", err
	}

	var random [bootstrapTokenBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate administrator token: %w", err)
	}
	token := hex.EncodeToString(random[:])
	for index := range random {
		random[index] = 0
	}

	document := principalConfig{
		Schema:        AdminConfigSchema,
		SchemaVersion: AdminConfigVersion,
		Principals: []PrincipalSpec{{
			ID:          administratorID,
			Role:        RoleAdmin,
			TokenSHA256: HashToken(token),
		}},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("encode administrator config: %w", err)
	}
	encoded = append(encoded, '\n')

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create administrator config: %w", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("restrict administrator config: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		return "", fmt.Errorf("write administrator config: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync administrator config: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close administrator config: %w", err)
	}
	keep = true
	return token, nil
}

func (signer *Signer) PublicKeyEncoded() (string, error) {
	if signer == nil || len(signer.publicKey) == 0 {
		return "", errors.New("signer is not initialized")
	}
	return base64.RawStdEncoding.EncodeToString(signer.publicKey), nil
}

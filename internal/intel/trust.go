package intel

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	maxTrustStoreBytes = 1 << 20
	maxTrustStoreKeys  = 1_024
)

var errFileChanged = errors.New("intel: local file changed while opening")

type trustStoreKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type trustStoreFile struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	Keys          []trustStoreKey `json:"keys"`
}

type TrustStore struct {
	keys map[string]ed25519.PublicKey
}

// LoadTrustStore loads pinned Ed25519 public keys from a regular, non-symlink
// file whose permissions are exactly 0600.
func LoadTrustStore(path string) (*TrustStore, error) {
	encoded, err := readSecureRegularFile(path, maxTrustStoreBytes)
	if err != nil {
		return nil, err
	}
	var document trustStoreFile
	if err := decodeStrict(encoded, &document); err != nil {
		return nil, ErrInvalidTrustStore
	}
	if document.Schema != TrustStoreSchema ||
		document.SchemaVersion != TrustStoreVersion ||
		len(document.Keys) == 0 ||
		len(document.Keys) > maxTrustStoreKeys {
		return nil, ErrInvalidTrustStore
	}

	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, entry := range document.Keys {
		if !boundedIdentifier(entry.KeyID, maxKeyIDBytes) {
			return nil, ErrInvalidTrustStore
		}
		if _, duplicate := keys[entry.KeyID]; duplicate {
			return nil, ErrInvalidTrustStore
		}
		decoded, err := base64.StdEncoding.DecodeString(entry.PublicKey)
		if err != nil ||
			len(decoded) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(decoded) != entry.PublicKey {
			return nil, ErrInvalidTrustStore
		}
		keys[entry.KeyID] = append(ed25519.PublicKey(nil), decoded...)
	}
	return &TrustStore{keys: keys}, nil
}

func (store *TrustStore) key(keyID string) (ed25519.PublicKey, bool) {
	if store == nil {
		return nil, false
	}
	publicKey, ok := store.keys[keyID]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), publicKey...), true
}

func readSecureRegularFile(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("intel: inspect local file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, ErrUnsafeFile
	}
	if before.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}
	if before.Size() > maxBytes {
		return nil, ErrBundleTooLarge
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("intel: open local file: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("intel: inspect opened file: %w", err)
	}
	if !after.Mode().IsRegular() {
		return nil, ErrUnsafeFile
	}
	if !os.SameFile(before, after) {
		return nil, errFileChanged
	}
	if after.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}

	encoded, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("intel: read local file: %w", err)
	}
	if int64(len(encoded)) > maxBytes {
		return nil, ErrBundleTooLarge
	}
	return encoded, nil
}

func trustStoreDocument(keyID string, publicKey ed25519.PublicKey) ([]byte, error) {
	if !boundedIdentifier(keyID, maxKeyIDBytes) || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("intel: invalid trust-store key")
	}
	return canonicalTrustStore(trustStoreFile{
		Schema:        TrustStoreSchema,
		SchemaVersion: TrustStoreVersion,
		Keys: []trustStoreKey{{
			KeyID:     keyID,
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}},
	})
}

func canonicalTrustStore(document trustStoreFile) ([]byte, error) {
	encoded, err := jsonMarshal(document)
	if err != nil {
		return nil, ErrInvalidTrustStore
	}
	return encoded, nil
}

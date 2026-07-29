package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Vardominator/oh-my-safety/internal/intel"
)

const (
	privateKeySchema        = "io.oh-my-safety/intelligence-private-key"
	privateKeySchemaVersion = 1
	maxPrivateKeyFileBytes  = 16 << 10
)

var (
	errInvalidJSON       = errors.New("intel-cli: invalid JSON input")
	errInvalidPrivateKey = errors.New("intel-cli: invalid private key file")
	errUnsafeLocalFile   = errors.New("intel-cli: expected a regular non-symlink file")
	errSensitiveMode     = errors.New("intel-cli: sensitive files must have mode 0600")
	errInputTooLarge     = errors.New("intel-cli: local input exceeds size limit")
	errRefuseOverwrite   = errors.New("intel-cli: refusing to overwrite an existing file")
	keyIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type privateKeyDocument struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	KeyID         string `json:"key_id"`
	PrivateKey    []byte `json:"private_key"`
}

type trustStoreKey struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type trustStoreDocument struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	Keys          []trustStoreKey `json:"keys"`
}

func loadPrivateKey(path string) (string, ed25519.PrivateKey, error) {
	encoded, err := readLocalFile(path, maxPrivateKeyFileBytes, true)
	if err != nil {
		return "", nil, err
	}
	defer clear(encoded)
	var document privateKeyDocument
	if err := decodeStrict(encoded, &document); err != nil {
		return "", nil, errInvalidPrivateKey
	}
	defer clear(document.PrivateKey)
	canonical, err := json.Marshal(document)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return "", nil, errInvalidPrivateKey
	}
	if document.Schema != privateKeySchema ||
		document.SchemaVersion != privateKeySchemaVersion ||
		!keyIDPattern.MatchString(document.KeyID) {
		return "", nil, errInvalidPrivateKey
	}
	if len(document.PrivateKey) != ed25519.PrivateKeySize {
		return "", nil, errInvalidPrivateKey
	}
	privateKey := ed25519.PrivateKey(append([]byte(nil), document.PrivateKey...))
	seed := privateKey.Seed()
	expected := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	valid := bytes.Equal(expected, privateKey)
	clear(expected)
	if !valid {
		clear(privateKey)
		return "", nil, errInvalidPrivateKey
	}
	return document.KeyID, privateKey, nil
}

func readLocalFile(path string, maxBytes int64, sensitive bool) ([]byte, error) {
	if path == "" || maxBytes <= 0 {
		return nil, errUnsafeLocalFile
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("intel-cli: cannot inspect local file")
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errUnsafeLocalFile
	}
	if sensitive && before.Mode().Perm() != 0o600 {
		return nil, errSensitiveMode
	}
	if before.Size() > maxBytes {
		return nil, errInputTooLarge
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("intel-cli: cannot open local file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, errors.New("intel-cli: cannot inspect opened file")
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errUnsafeLocalFile
	}
	if sensitive && after.Mode().Perm() != 0o600 {
		return nil, errSensitiveMode
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, errors.New("intel-cli: cannot read local file")
	}
	if int64(len(encoded)) > maxBytes {
		return nil, errInputTooLarge
	}
	return encoded, nil
}

func writeExclusive(path string, content []byte) error {
	if path == "" {
		return errUsage
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return errRefuseOverwrite
	}
	if err != nil {
		return errors.New("intel-cli: cannot create local output")
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("intel-cli: cannot secure local output")
	}
	if err := writeAll(file, content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return errors.New("intel-cli: cannot sync local output")
	}
	if err := file.Close(); err != nil {
		return errors.New("intel-cli: cannot close local output")
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func writeAll(destination io.Writer, content []byte) error {
	for len(content) > 0 {
		count, err := destination.Write(content)
		if err != nil {
			return errors.New("intel-cli: cannot write local output")
		}
		if count == 0 {
			return errors.New("intel-cli: short local output write")
		}
		content = content[count:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("intel-cli: cannot open output directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("intel-cli: cannot sync output directory")
	}
	return nil
}

func pathAvailable(path string) error {
	if path == "" {
		return errUsage
	}
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return errRefuseOverwrite
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return errors.New("intel-cli: cannot inspect output path")
	}
}

func decodeStrict(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errInvalidJSON
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

func trustDocument(keyID string, publicKey ed25519.PublicKey) ([]byte, error) {
	document := trustStoreDocument{
		Schema:        intel.TrustStoreSchema,
		SchemaVersion: intel.TrustStoreVersion,
		Keys: []trustStoreKey{{
			KeyID:     keyID,
			PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		}},
	}
	return json.Marshal(document)
}

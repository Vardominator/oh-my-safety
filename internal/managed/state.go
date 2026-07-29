// Package managed implements the enrolled endpoint side of the organization
// controller protocol. It is deliberately pull-only: enrolled agents initiate
// HTTPS requests and never accept controller-originated connections or code.
package managed

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	StateSchema        = "io.oh-my-safety/managed-enrollment"
	StateSchemaVersion = 1
	maxStateBytes      = 32 << 10
)

type EnrollmentState struct {
	Schema           string    `json:"schema"`
	SchemaVersion    int       `json:"schema_version"`
	ControllerURL    string    `json:"controller_url"`
	DeviceID         string    `json:"device_id"`
	DeviceCredential string    `json:"device_credential"`
	PolicyPublicKey  string    `json:"policy_public_key"`
	EnrolledAt       time.Time `json:"enrolled_at"`
}

func (state EnrollmentState) Validate() error {
	if state.Schema != StateSchema || state.SchemaVersion != StateSchemaVersion {
		return errors.New("unsupported managed enrollment state schema")
	}
	canonicalURL, err := validateControllerURL(state.ControllerURL)
	if err != nil || canonicalURL != state.ControllerURL {
		return errors.New("managed enrollment state has an invalid controller URL")
	}
	if !safeIdentifier(state.DeviceID, 128) {
		return errors.New("managed enrollment state has an invalid device id")
	}
	if !safeCredential(state.DeviceCredential) {
		return errors.New("managed enrollment state has an invalid device credential")
	}
	if _, err := decodePublicKey(state.PolicyPublicKey); err != nil {
		return errors.New("managed enrollment state has an invalid policy public key")
	}
	if state.EnrolledAt.IsZero() {
		return errors.New("managed enrollment state has no enrollment timestamp")
	}
	return nil
}

func LoadState(path string) (EnrollmentState, error) {
	if strings.TrimSpace(path) == "" {
		return EnrollmentState{}, errors.New("managed enrollment state path is required")
	}
	initialInfo, err := os.Lstat(path)
	if err != nil {
		return EnrollmentState{}, fmt.Errorf("inspect managed enrollment state: %w", err)
	}
	if !initialInfo.Mode().IsRegular() || initialInfo.Mode().Perm() != 0o600 {
		return EnrollmentState{}, errors.New(
			"managed enrollment state must be a regular non-symlink mode-600 file",
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return EnrollmentState{}, errors.New("open managed enrollment state")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return EnrollmentState{}, errors.New("inspect opened managed enrollment state")
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 ||
		!os.SameFile(initialInfo, openedInfo) {
		return EnrollmentState{}, errors.New("managed enrollment state changed while opening it")
	}
	if openedInfo.Size() > maxStateBytes {
		return EnrollmentState{}, errors.New("managed enrollment state exceeds its size limit")
	}
	var state EnrollmentState
	if err := decodeStrict(io.LimitReader(file, maxStateBytes+1), &state); err != nil {
		return EnrollmentState{}, errors.New("decode managed enrollment state")
	}
	if err := state.Validate(); err != nil {
		return EnrollmentState{}, err
	}
	return state, nil
}

func createState(path string, state EnrollmentState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("managed enrollment state already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect managed enrollment state destination")
	}
	parent, err := ensurePrivateStateDirectory(path)
	if err != nil {
		return err
	}
	temporary, err := writeTemporaryState(parent, state)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("managed enrollment state already exists")
		}
		return errors.New("install managed enrollment state")
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	return nil
}

func replaceState(path string, state EnrollmentState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("inspect managed enrollment state before update")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New(
			"managed enrollment state must be a regular non-symlink mode-600 file",
		)
	}
	parent, err := ensurePrivateStateDirectory(path)
	if err != nil {
		return err
	}
	temporary, err := writeTemporaryState(parent, state)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("replace managed enrollment state")
	}
	return syncDirectory(parent)
}

func ensurePrivateStateDirectory(statePath string) (string, error) {
	parent := filepath.Dir(statePath)
	if parent == "" {
		parent = "."
	}
	info, err := os.Lstat(parent)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", errors.New("create managed state directory")
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			return "", errors.New("restrict managed state directory")
		}
		info, err = os.Lstat(parent)
	case err != nil:
		return "", errors.New("inspect managed state directory")
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("managed state parent must be a non-symlink directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("managed state parent must not be accessible by group or other")
	}
	return parent, nil
}

func writeTemporaryState(parent string, state EnrollmentState) (string, error) {
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", errors.New("encode managed enrollment state")
	}
	if len(encoded) > maxStateBytes {
		return "", errors.New("managed enrollment state exceeds its size limit")
	}
	encoded = append(encoded, '\n')
	file, err := os.CreateTemp(parent, ".managed-state-*")
	if err != nil {
		return "", errors.New("create temporary managed enrollment state")
	}
	name := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(name)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return "", errors.New("restrict temporary managed enrollment state")
	}
	if _, err := file.Write(encoded); err != nil {
		cleanup()
		return "", errors.New("write managed enrollment state")
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", errors.New("sync managed enrollment state")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", errors.New("close managed enrollment state")
	}
	return name, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("open managed state directory for sync")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync managed state directory")
	}
	return nil
}

func validateControllerURL(raw string) (string, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return "", errors.New("controller URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("controller URL must be an origin without credentials, query, or path")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !loopbackHostname(parsed.Hostname()) {
			return "", errors.New("HTTP controller URLs are allowed only for loopback hosts")
		}
	default:
		return "", errors.New("controller URL must use HTTPS")
	}
	if parsed.Port() == "" {
		switch parsed.Scheme {
		case "https":
		default:
			return "", errors.New("loopback HTTP controller URL must include a port")
		}
	}
	parsed.Path = ""
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func loopbackHostname(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("policy public key must be raw-base64 Ed25519 key material")
	}
	if base64.RawStdEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("policy public key is not canonical raw base64")
	}
	return ed25519.PublicKey(decoded), nil
}

func safeIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func safeCredential(value string) bool {
	if len(value) < 32 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func decodeStrict(reader io.Reader, destination any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

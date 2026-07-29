package controller

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	maxAdminConfigBytes = 64 << 10
	maxBearerTokenBytes = 4 << 10
)

type PrincipalSpec struct {
	ID          string `json:"id"`
	Role        Role   `json:"role"`
	TokenSHA256 string `json:"token_sha256"`
}

type principalConfig struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	Principals    []PrincipalSpec `json:"principals"`
}

type PrincipalSet struct {
	principals []Principal
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func NewPrincipalSet(specifications []PrincipalSpec) (*PrincipalSet, error) {
	if len(specifications) == 0 || len(specifications) > 1_000 {
		return nil, errors.New("principal config must contain between 1 and 1000 principals")
	}
	principals := make([]Principal, 0, len(specifications))
	ids := make(map[string]struct{}, len(specifications))
	tokenHashes := make(map[[sha256.Size]byte]struct{}, len(specifications))
	hasAdmin := false
	for _, specification := range specifications {
		if !validIdentifier(specification.ID) {
			return nil, errors.New("principal config contains an invalid id")
		}
		if !specification.Role.Valid() {
			return nil, errors.New("principal config contains an invalid role")
		}
		if _, exists := ids[specification.ID]; exists {
			return nil, errors.New("principal config contains a duplicate id")
		}
		decoded, err := hex.DecodeString(specification.TokenSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("principal config contains an invalid token hash")
		}
		var tokenHash [sha256.Size]byte
		copy(tokenHash[:], decoded)
		for index := range decoded {
			decoded[index] = 0
		}
		if _, exists := tokenHashes[tokenHash]; exists {
			return nil, errors.New("principal config contains a duplicate token hash")
		}
		principals = append(principals, Principal{
			ID:        specification.ID,
			Role:      specification.Role,
			tokenHash: tokenHash,
		})
		ids[specification.ID] = struct{}{}
		tokenHashes[tokenHash] = struct{}{}
		hasAdmin = hasAdmin || specification.Role == RoleAdmin
	}
	if !hasAdmin {
		return nil, errors.New("principal config must contain at least one admin")
	}
	return &PrincipalSet{principals: principals}, nil
}

func LoadPrincipalSet(path string) (*PrincipalSet, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("admin config path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect admin config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("admin config must be a regular mode-600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open admin config: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened admin config: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 ||
		!os.SameFile(info, openedInfo) {
		return nil, errors.New("admin config changed while opening it")
	}

	var config principalConfig
	if err := decodeStrictReader(io.LimitReader(file, maxAdminConfigBytes+1), &config); err != nil {
		return nil, fmt.Errorf("decode admin config: %w", err)
	}
	if openedInfo.Size() > maxAdminConfigBytes {
		return nil, errors.New("admin config exceeds size limit")
	}
	if config.Schema != AdminConfigSchema ||
		config.SchemaVersion != AdminConfigVersion {
		return nil, errors.New("unsupported admin config schema")
	}
	return NewPrincipalSet(config.Principals)
}

// AuthenticateBearer hashes the presented token and compares it against every
// configured digest. Comparisons never short-circuit and use constant-time
// equality. Callers must return the same response for every false result.
func (set *PrincipalSet) AuthenticateBearer(header string) (Principal, bool) {
	var candidate string
	validFormat := 0
	if len(header) <= len("Bearer ")+maxBearerTokenBytes &&
		strings.HasPrefix(header, "Bearer ") &&
		len(header) > len("Bearer ") {
		candidate = header[len("Bearer "):]
		if !strings.ContainsAny(candidate, " \t\r\n") {
			validFormat = 1
		}
	}
	candidateHash := sha256.Sum256([]byte(candidate))
	selected := -1
	for index := range set.principals {
		equal := subtle.ConstantTimeCompare(candidateHash[:], set.principals[index].tokenHash[:])
		if equal&validFormat == 1 {
			selected = index
		}
	}
	if selected < 0 {
		return Principal{}, false
	}
	return set.principals[selected], true
}

func decodeStrictReader(reader io.Reader, destination any) error {
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

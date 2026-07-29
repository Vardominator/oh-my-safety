package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	signingKeySchema        = "io.oh-my-safety/controller-signing-key"
	signingKeySchemaVersion = 1
	maxSigningKeyFileBytes  = 8 << 10
)

type signingKeyFile struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	PrivateKey    string `json:"private_key"`
}

type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func LoadOrCreateSigner(path string) (*Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("signing key path is required")
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		return loadSigner(path, info)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("inspect signing key: %w", err)
	}

	if err := ensureNewPrivateParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	signerPrivateKey := append(ed25519.PrivateKey(nil), privateKey...)
	signerPublicKey := append(ed25519.PublicKey(nil), publicKey...)
	document := signingKeyFile{
		Schema:        signingKeySchema,
		SchemaVersion: signingKeySchemaVersion,
		PrivateKey:    base64.RawStdEncoding.EncodeToString(privateKey),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	document.PrivateKey = ""
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		info, inspectErr := os.Lstat(path)
		if inspectErr != nil {
			return nil, fmt.Errorf("inspect concurrently created signing key: %w", inspectErr)
		}
		return loadSigner(path, info)
	}
	if err != nil {
		return nil, fmt.Errorf("create signing key: %w", err)
	}
	writeErr := func() error {
		defer file.Close()
		if _, err := file.Write(encoded); err != nil {
			return fmt.Errorf("write signing key: %w", err)
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync signing key: %w", err)
		}
		return nil
	}()
	for index := range privateKey {
		privateKey[index] = 0
	}
	if writeErr != nil {
		for index := range signerPrivateKey {
			signerPrivateKey[index] = 0
		}
		return nil, writeErr
	}
	for index := range encoded {
		encoded[index] = 0
	}
	return &Signer{
		privateKey: signerPrivateKey,
		publicKey:  signerPublicKey,
	}, nil
}

func loadSigner(path string, initialInfo os.FileInfo) (*Signer, error) {
	if !initialInfo.Mode().IsRegular() || initialInfo.Mode().Perm() != 0o600 {
		return nil, errors.New("signing key must be a regular mode-600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open signing key: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened signing key: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 ||
		!os.SameFile(initialInfo, openedInfo) {
		return nil, errors.New("signing key changed while opening it")
	}
	if openedInfo.Size() > maxSigningKeyFileBytes {
		return nil, errors.New("signing key file exceeds size limit")
	}
	var document signingKeyFile
	if err := decodeStrictReader(io.LimitReader(file, maxSigningKeyFileBytes+1), &document); err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if document.Schema != signingKeySchema ||
		document.SchemaVersion != signingKeySchemaVersion {
		return nil, errors.New("unsupported signing key schema")
	}
	decoded, err := base64.RawStdEncoding.DecodeString(document.PrivateKey)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key contains invalid private key material")
	}
	privateKey := append(ed25519.PrivateKey(nil), decoded...)
	for index := range decoded {
		decoded[index] = 0
	}
	publicKey := append(ed25519.PublicKey(nil), privateKey[32:]...)
	return &Signer{privateKey: privateKey, publicKey: publicKey}, nil
}

func ensureNewPrivateParent(parent string) error {
	if parent == "" || parent == "." {
		return nil
	}
	_, err := os.Stat(parent)
	switch {
	case err == nil:
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return fmt.Errorf("restrict private directory: %w", err)
	}
	return nil
}

func (signer *Signer) Sign(document PolicyDocument) (SignedPolicy, error) {
	if signer == nil || len(signer.privateKey) != ed25519.PrivateKeySize {
		return SignedPolicy{}, errors.New("signer is not initialized")
	}
	if err := document.Validate(); err != nil {
		return SignedPolicy{}, err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return SignedPolicy{}, fmt.Errorf("encode policy for signing: %w", err)
	}
	signature := ed25519.Sign(signer.privateKey, encoded)
	return SignedPolicy{
		Schema:           SignedPolicySchema,
		SchemaVersion:    SignedPolicyVersion,
		Document:         document,
		Algorithm:        "Ed25519",
		SigningPublicKey: base64.RawStdEncoding.EncodeToString(signer.publicKey),
		Signature:        base64.RawStdEncoding.EncodeToString(signature),
	}, nil
}

func VerifySignedPolicy(policy SignedPolicy) error {
	if policy.Schema != SignedPolicySchema ||
		policy.SchemaVersion != SignedPolicyVersion ||
		policy.Algorithm != "Ed25519" {
		return errors.New("unsupported signed policy envelope")
	}
	if err := policy.Document.Validate(); err != nil {
		return err
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(policy.SigningPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid policy signing public key")
	}
	signature, err := base64.RawStdEncoding.DecodeString(policy.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid policy signature")
	}
	encoded, err := json.Marshal(policy.Document)
	if err != nil {
		return fmt.Errorf("encode policy for verification: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), encoded, signature) {
		return errors.New("policy signature verification failed")
	}
	return nil
}

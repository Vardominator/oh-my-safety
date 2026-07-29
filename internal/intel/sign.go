package intel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"
)

// Sign canonicalizes bundle records, computes the declarative payload digest,
// and returns the signed bundle plus its canonical JSON representation.
func Sign(
	bundle Bundle,
	keyID string,
	privateKey ed25519.PrivateKey,
	limits Limits,
) (Bundle, []byte, error) {
	resolvedLimits, err := normalizeLimits(limits)
	if err != nil {
		return Bundle{}, nil, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Bundle{}, nil, errors.New("intel: invalid Ed25519 private key")
	}
	if bundle.Schema == "" {
		bundle.Schema = BundleSchema
	}
	if bundle.SchemaVersion == 0 {
		bundle.SchemaVersion = BundleSchemaVersion
	}
	bundle.KeyID = keyID
	bundle.PayloadSHA256 = ""
	bundle.Signature = ""

	prepared, payload, err := prepareBundle(bundle, resolvedLimits)
	if err != nil {
		return Bundle{}, nil, err
	}
	prepared.PayloadSHA256 = hashBytes(payload)
	unsigned, err := canonicalUnsigned(prepared)
	if err != nil {
		return Bundle{}, nil, ErrInvalidBundle
	}
	prepared.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	canonical, err := canonicalBundle(prepared)
	if err != nil {
		return Bundle{}, nil, ErrInvalidBundle
	}
	if int64(len(canonical)) > resolvedLimits.MaxBundleBytes {
		return Bundle{}, nil, ErrBundleTooLarge
	}
	return prepared, canonical, nil
}

// Canonicalize returns canonical JSON for an already signed bundle. It does not
// establish trust; callers must use Verify before consuming or installing it.
func Canonicalize(bundle Bundle, limits Limits) ([]byte, error) {
	resolvedLimits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	prepared, _, err := prepareBundle(bundle, resolvedLimits)
	if err != nil {
		return nil, err
	}
	if !sha256Pattern.MatchString(prepared.PayloadSHA256) || prepared.Signature == "" {
		return nil, ErrInvalidBundle
	}
	canonical, err := canonicalBundle(prepared)
	if err != nil {
		return nil, ErrInvalidBundle
	}
	if int64(len(canonical)) > resolvedLimits.MaxBundleBytes {
		return nil, ErrBundleTooLarge
	}
	return canonical, nil
}

func Verify(
	encoded []byte,
	trustStore *TrustStore,
	options VerifyOptions,
) (VerifiedBundle, error) {
	resolvedLimits, err := normalizeLimits(options.Limits)
	if err != nil {
		return VerifiedBundle{}, err
	}
	if int64(len(encoded)) > resolvedLimits.MaxBundleBytes {
		return VerifiedBundle{}, ErrBundleTooLarge
	}
	if trustStore == nil {
		return VerifiedBundle{}, ErrUnknownKey
	}

	var decoded Bundle
	if err := decodeStrict(encoded, &decoded); err != nil {
		return VerifiedBundle{}, err
	}
	if len(decoded.Records) > resolvedLimits.MaxRecords {
		return VerifiedBundle{}, ErrTooManyRecords
	}
	prepared, payload, err := prepareBundle(decoded, resolvedLimits)
	if err != nil {
		return VerifiedBundle{}, err
	}
	canonical, err := canonicalBundle(prepared)
	if err != nil {
		return VerifiedBundle{}, ErrInvalidBundle
	}
	if !bytes.Equal(encoded, canonical) {
		return VerifiedBundle{}, ErrNonCanonical
	}
	if !sha256Pattern.MatchString(prepared.PayloadSHA256) ||
		prepared.PayloadSHA256 != hashBytes(payload) {
		return VerifiedBundle{}, ErrPayloadHashMismatch
	}

	publicKey, ok := trustStore.key(prepared.KeyID)
	if !ok {
		return VerifiedBundle{}, ErrUnknownKey
	}
	signature, err := base64.StdEncoding.DecodeString(prepared.Signature)
	if err != nil ||
		len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != prepared.Signature {
		return VerifiedBundle{}, ErrInvalidSignature
	}
	unsigned, err := canonicalUnsigned(prepared)
	if err != nil || !ed25519.Verify(publicKey, unsigned, signature) {
		return VerifiedBundle{}, ErrInvalidSignature
	}

	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if options.ClockSkew < 0 {
		return VerifiedBundle{}, ErrInvalidBundle
	}
	if now.Add(options.ClockSkew).Before(prepared.IssuedAt) {
		return VerifiedBundle{}, ErrNotYetValid
	}
	if now.Add(-options.ClockSkew).After(prepared.ExpiresAt) {
		return VerifiedBundle{}, ErrExpired
	}
	agentSchema := options.AgentSchema
	if agentSchema <= 0 {
		agentSchema = 1
	}
	if prepared.MinimumAgentSchema > agentSchema {
		return VerifiedBundle{}, ErrAgentSchema
	}

	replay := false
	if previous := options.LastAccepted; previous != nil && previous.Sequence > 0 {
		switch {
		case prepared.Sequence < previous.Sequence:
			return VerifiedBundle{}, ErrRollback
		case prepared.Sequence == previous.Sequence &&
			prepared.BundleID == previous.BundleID &&
			prepared.PayloadSHA256 == previous.PayloadSHA256:
			replay = true
		case prepared.Sequence == previous.Sequence:
			return VerifiedBundle{}, ErrSequenceConflict
		}
	}
	return VerifiedBundle{
		Bundle:    prepared,
		Canonical: append([]byte(nil), canonical...),
		Replay:    replay,
	}, nil
}

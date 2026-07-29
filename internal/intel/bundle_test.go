package intel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var testClock = time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)

func testKey(fill byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func testTrust(publicKey ed25519.PublicKey) *TrustStore {
	return &TrustStore{keys: map[string]ed25519.PublicKey{
		"release-2026": append(ed25519.PublicKey(nil), publicKey...),
	}}
}

func testBundle(sequence uint64) Bundle {
	return Bundle{
		BundleID:           "stable",
		Sequence:           sequence,
		IssuedAt:           testClock.Add(-time.Hour),
		ExpiresAt:          testClock.Add(time.Hour),
		MinimumAgentSchema: 1,
		Records: []Record{
			{
				Type: RecordMaliciousSHA256,
				MaliciousSHA256: &MaliciousSHA256Record{
					SHA256: strings.Repeat("A", 64),
				},
			},
			{
				Type: RecordRevokedSigner,
				RevokedSigner: &RevokedSignerRecord{
					Kind: TeamID, Identifier: "ABC123DE45",
				},
			},
			{
				Type: RecordVulnerablePackage,
				VulnerablePackage: &VulnerablePackageRecord{
					Ecosystem: "NPM",
					Package:   "@scope/package",
					Constraints: []VersionConstraint{
						{Operator: ConstraintLessThan, Version: "2.0.0"},
						{Operator: ConstraintGreaterThanOrEqual, Version: "1.0.0"},
					},
				},
			},
			{
				Type: RecordSecretPattern,
				SecretPattern: &SecretDetectorPatternRecord{
					DetectorID: "example-api-key",
					Pattern:    `(?i)api[_-]?key=[A-Za-z0-9]{16,64}`,
				},
			},
		},
	}
}

func signTestBundle(t *testing.T, bundle Bundle, privateKey ed25519.PrivateKey) (Bundle, []byte) {
	t.Helper()
	signed, encoded, err := Sign(bundle, "release-2026", privateKey, Limits{})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return signed, encoded
}

func verifyTestBundle(t *testing.T, encoded []byte, trust *TrustStore) VerifiedBundle {
	t.Helper()
	verified, err := Verify(encoded, trust, VerifyOptions{
		Now:         testClock,
		AgentSchema: 1,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return verified
}

func TestSignVerifyRoundTrip(t *testing.T) {
	publicKey, privateKey := testKey(1)
	signed, encoded := signTestBundle(t, testBundle(7), privateKey)
	verified := verifyTestBundle(t, encoded, testTrust(publicKey))

	if verified.Replay {
		t.Fatal("new bundle reported as replay")
	}
	if !bytes.Equal(verified.Canonical, encoded) {
		t.Fatal("verified bytes differ from signed canonical bytes")
	}
	if verified.Bundle.PayloadSHA256 != signed.PayloadSHA256 {
		t.Fatal("payload digest changed")
	}
	if got := verified.Bundle.Records[0].MaliciousSHA256.SHA256; got != strings.Repeat("a", 64) {
		t.Fatalf("normalized hash = %q", got)
	}
	if got := verified.Bundle.Records[3].VulnerablePackage.Ecosystem; got != "npm" {
		t.Fatalf("normalized ecosystem = %q", got)
	}
}

func TestCanonicalSigningIsDeterministic(t *testing.T) {
	_, privateKey := testKey(2)
	first := testBundle(8)
	second := testBundle(8)
	for left, right := 0, len(second.Records)-1; left < right; left, right = left+1, right-1 {
		second.Records[left], second.Records[right] = second.Records[right], second.Records[left]
	}
	for _, record := range second.Records {
		if record.VulnerablePackage != nil {
			constraints := record.VulnerablePackage.Constraints
			constraints[0], constraints[1] = constraints[1], constraints[0]
		}
	}

	signedFirst, encodedFirst := signTestBundle(t, first, privateKey)
	signedSecond, encodedSecond := signTestBundle(t, second, privateKey)
	if !bytes.Equal(encodedFirst, encodedSecond) {
		t.Fatalf("canonical encodings differ:\n%s\n%s", encodedFirst, encodedSecond)
	}
	if signedFirst.Signature != signedSecond.Signature {
		t.Fatal("deterministic Ed25519 signatures differ")
	}
}

func TestVerifyRejectsTamperingAndWrongKeys(t *testing.T) {
	publicKey, privateKey := testKey(3)
	otherPublic, _ := testKey(4)
	signed, encoded := signTestBundle(t, testBundle(9), privateKey)

	t.Run("payload", func(t *testing.T) {
		tampered := signed
		tampered.Records = append([]Record(nil), signed.Records...)
		changed := *tampered.Records[0].MaliciousSHA256
		changed.SHA256 = strings.Repeat("b", 64)
		tampered.Records[0].MaliciousSHA256 = &changed
		tamperedJSON, err := canonicalBundle(tampered)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(tamperedJSON, testTrust(publicKey), VerifyOptions{Now: testClock})
		if !errors.Is(err, ErrPayloadHashMismatch) {
			t.Fatalf("Verify() error = %v, want payload mismatch", err)
		}
	})

	t.Run("signature", func(t *testing.T) {
		tampered := signed
		signature, err := base64.StdEncoding.DecodeString(tampered.Signature)
		if err != nil {
			t.Fatal(err)
		}
		signature[0] ^= 0xff
		tampered.Signature = base64.StdEncoding.EncodeToString(signature)
		tamperedJSON, _ := canonicalBundle(tampered)
		_, err = Verify(tamperedJSON, testTrust(publicKey), VerifyOptions{Now: testClock})
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Verify() error = %v, want invalid signature", err)
		}
	})

	t.Run("noncanonical signature base64", func(t *testing.T) {
		tampered := signed
		tampered.Signature = nonCanonicalBase64(t, tampered.Signature)
		tamperedJSON, _ := canonicalBundle(tampered)
		_, err := Verify(tamperedJSON, testTrust(publicKey), VerifyOptions{Now: testClock})
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Verify() error = %v, want invalid signature", err)
		}
	})

	t.Run("wrong pinned key", func(t *testing.T) {
		_, err := Verify(encoded, testTrust(otherPublic), VerifyOptions{Now: testClock})
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Verify() error = %v, want invalid signature", err)
		}
	})

	t.Run("unknown key id", func(t *testing.T) {
		_, err := Verify(encoded, &TrustStore{keys: map[string]ed25519.PublicKey{}}, VerifyOptions{
			Now: testClock,
		})
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("Verify() error = %v, want unknown key", err)
		}
	})

	t.Run("noncanonical", func(t *testing.T) {
		pretty := new(bytes.Buffer)
		if err := json.Indent(pretty, encoded, "", "  "); err != nil {
			t.Fatal(err)
		}
		_, err := Verify(pretty.Bytes(), testTrust(publicKey), VerifyOptions{Now: testClock})
		if !errors.Is(err, ErrNonCanonical) {
			t.Fatalf("Verify() error = %v, want noncanonical", err)
		}
	})
}

func nonCanonicalBase64(t *testing.T, encoded string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	value := []byte(encoded)
	position := len(value) - 2
	if strings.HasSuffix(encoded, "==") {
		position = len(value) - 3
	}
	index := strings.IndexByte(alphabet, value[position])
	if index < 0 || index == len(alphabet)-1 {
		t.Fatalf("cannot alter base64 encoding %q", encoded)
	}
	value[position] = alphabet[index+1]
	return string(value)
}

func TestVerifyTimeSchemaAndSequencePolicy(t *testing.T) {
	publicKey, privateKey := testKey(5)
	signed, encoded := signTestBundle(t, testBundle(10), privateKey)
	trust := testTrust(publicKey)

	tests := []struct {
		name    string
		options VerifyOptions
		wantErr error
		replay  bool
	}{
		{
			name:    "expired",
			options: VerifyOptions{Now: signed.ExpiresAt.Add(time.Nanosecond)},
			wantErr: ErrExpired,
		},
		{
			name:    "not yet valid",
			options: VerifyOptions{Now: signed.IssuedAt.Add(-time.Nanosecond)},
			wantErr: ErrNotYetValid,
		},
		{
			name: "expiry within skew",
			options: VerifyOptions{
				Now: signed.ExpiresAt.Add(time.Second), ClockSkew: 2 * time.Second,
			},
		},
		{
			name: "issuance within skew",
			options: VerifyOptions{
				Now: signed.IssuedAt.Add(-time.Second), ClockSkew: 2 * time.Second,
			},
		},
		{
			name:    "agent schema",
			options: VerifyOptions{Now: testClock, AgentSchema: 0},
		},
		{
			name: "exact replay",
			options: VerifyOptions{Now: testClock, LastAccepted: &AcceptanceState{
				BundleID: signed.BundleID, Sequence: signed.Sequence,
				PayloadSHA256: signed.PayloadSHA256,
			}},
			replay: true,
		},
		{
			name: "rollback",
			options: VerifyOptions{Now: testClock, LastAccepted: &AcceptanceState{
				BundleID: signed.BundleID, Sequence: signed.Sequence + 1,
				PayloadSHA256: signed.PayloadSHA256,
			}},
			wantErr: ErrRollback,
		},
		{
			name: "sequence conflict",
			options: VerifyOptions{Now: testClock, LastAccepted: &AcceptanceState{
				BundleID: "different", Sequence: signed.Sequence,
				PayloadSHA256: strings.Repeat("0", 64),
			}},
			wantErr: ErrSequenceConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified, err := Verify(encoded, trust, test.options)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, test.wantErr)
			}
			if err == nil && verified.Replay != test.replay {
				t.Fatalf("Replay = %t, want %t", verified.Replay, test.replay)
			}
		})
	}

	requiresNewSchema := testBundle(11)
	requiresNewSchema.MinimumAgentSchema = 2
	_, schemaJSON := signTestBundle(t, requiresNewSchema, privateKey)
	_, err := Verify(schemaJSON, trust, VerifyOptions{Now: testClock, AgentSchema: 1})
	if !errors.Is(err, ErrAgentSchema) {
		t.Fatalf("Verify() error = %v, want agent schema error", err)
	}
}

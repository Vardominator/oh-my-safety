package managed

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Vardominator/oh-my-safety/internal/controller"
)

const (
	PolicyFileName               = "managed-policy.json"
	policyRevisionLedgerFileName = "managed-policy-revisions.json"
	policyRevisionLedgerSchema   = "io.oh-my-safety/managed-policy-revisions"
	policyRevisionLedgerVersion  = 1
	maxPolicyFileBytes           = 256 << 10
	maxPolicyRevisionLedgerBytes = 1 << 20
	maxRememberedPolicyIDs       = 4_096
)

var (
	errPolicyNotFound = errors.New("managed policy not found")
	errLedgerNotFound = errors.New("managed policy revision ledger not found")
)

type policyRevisionLedger struct {
	Schema        string                `json:"schema"`
	SchemaVersion int                   `json:"schema_version"`
	Policies      []policyRevisionEntry `json:"policies"`
}

type policyRevisionEntry struct {
	PolicyID        string `json:"policy_id"`
	HighestRevision uint64 `json:"highest_revision"`
	DocumentSHA256  string `json:"document_sha256"`
}

func PolicyPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), PolicyFileName)
}

func policyRevisionLedgerPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), policyRevisionLedgerFileName)
}

func LoadPolicy(statePath string) (controller.PolicyDocument, error) {
	state, err := LoadState(statePath)
	if err != nil {
		return controller.PolicyDocument{}, err
	}
	signed, err := loadSignedPolicyFile(PolicyPath(statePath))
	if err != nil {
		return controller.PolicyDocument{}, err
	}
	if err := verifyPinnedPolicy(state.PolicyPublicKey, signed); err != nil {
		return controller.PolicyDocument{}, err
	}
	ledger, err := loadPolicyRevisionLedger(policyRevisionLedgerPath(statePath))
	if err != nil {
		return controller.PolicyDocument{}, err
	}
	if err := ledger.verifyCurrent(signed.Document); err != nil {
		return controller.PolicyDocument{}, err
	}
	return signed.Document, nil
}

func loadSignedPolicyFile(path string) (controller.SignedPolicy, error) {
	initialInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return controller.SignedPolicy{}, errPolicyNotFound
	}
	if err != nil {
		return controller.SignedPolicy{}, errors.New("inspect managed policy")
	}
	if !initialInfo.Mode().IsRegular() || initialInfo.Mode().Perm() != 0o600 {
		return controller.SignedPolicy{}, errors.New(
			"managed policy must be a regular non-symlink mode-600 file",
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return controller.SignedPolicy{}, errors.New("open managed policy")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return controller.SignedPolicy{}, errors.New("inspect opened managed policy")
	}
	if !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm() != 0o600 ||
		!os.SameFile(initialInfo, openedInfo) {
		return controller.SignedPolicy{}, errors.New("managed policy changed while opening it")
	}
	if openedInfo.Size() > maxPolicyFileBytes {
		return controller.SignedPolicy{}, errors.New("managed policy exceeds its size limit")
	}
	var signed controller.SignedPolicy
	if err := decodeStrict(
		io.LimitReader(file, maxPolicyFileBytes+1),
		&signed,
	); err != nil {
		return controller.SignedPolicy{}, errors.New("decode managed policy")
	}
	return signed, nil
}

func persistVerifiedPolicy(
	statePath string,
	signed controller.SignedPolicy,
) (string, error) {
	state, err := LoadState(statePath)
	if err != nil {
		return "", err
	}
	if err := verifyPinnedPolicy(state.PolicyPublicKey, signed); err != nil {
		return "", err
	}
	document := signed.Document
	path := PolicyPath(statePath)
	parent, err := ensurePrivateStateDirectory(path)
	if err != nil {
		return "", err
	}
	release, err := acquirePolicyWriteLock(parent)
	if err != nil {
		return "", err
	}
	defer release()

	existingSigned, loadErr := loadSignedPolicyFile(path)
	switch {
	case loadErr == nil:
		if err := verifyPinnedPolicy(state.PolicyPublicKey, existingSigned); err != nil {
			return "", errors.New("cached managed policy signature is invalid")
		}
	case errors.Is(loadErr, errPolicyNotFound):
	default:
		return "", loadErr
	}

	ledgerPath := policyRevisionLedgerPath(statePath)
	ledger, ledgerErr := loadPolicyRevisionLedger(ledgerPath)
	ledgerMissing := errors.Is(ledgerErr, errLedgerNotFound)
	switch {
	case ledgerErr == nil:
	case ledgerMissing:
		ledger = policyRevisionLedger{
			Schema:        policyRevisionLedgerSchema,
			SchemaVersion: policyRevisionLedgerVersion,
		}
		if loadErr == nil {
			if _, err := ledger.observe(existingSigned.Document); err != nil {
				return "", err
			}
		}
	default:
		return "", ledgerErr
	}
	ledgerChanged, err := ledger.observe(document)
	if err != nil {
		return "", err
	}
	if ledgerMissing || ledgerChanged {
		if err := persistPolicyRevisionLedger(parent, ledgerPath, ledger); err != nil {
			return "", err
		}
	}
	if loadErr == nil &&
		existingSigned.Document.ID == document.ID &&
		existingSigned.Document.Revision == document.Revision {
		equal, err := policiesEqual(existingSigned.Document, document)
		if err != nil {
			return "", err
		}
		if equal {
			return path, nil
		}
	}

	encoded, err := json.Marshal(signed)
	if err != nil || len(encoded) > maxPolicyFileBytes {
		return "", errors.New("encode verified managed policy")
	}
	encoded = append(encoded, '\n')
	temporary, err := writeTemporaryPolicy(parent, encoded)
	if err != nil {
		return "", err
	}
	defer os.Remove(temporary)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.Link(temporary, path); err != nil {
			return "", errors.New("install verified managed policy")
		}
	} else if err != nil {
		return "", errors.New("inspect managed policy destination")
	} else {
		if err := os.Rename(temporary, path); err != nil {
			return "", errors.New("replace verified managed policy")
		}
	}
	if err := syncDirectory(parent); err != nil {
		return "", err
	}
	return path, nil
}

func loadPolicyRevisionLedger(path string) (policyRevisionLedger, error) {
	initialInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return policyRevisionLedger{}, errLedgerNotFound
	}
	if err != nil {
		return policyRevisionLedger{}, errors.New("inspect managed policy revision ledger")
	}
	if !initialInfo.Mode().IsRegular() || initialInfo.Mode().Perm() != 0o600 {
		return policyRevisionLedger{}, errors.New(
			"managed policy revision ledger must be a regular non-symlink mode-600 file",
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return policyRevisionLedger{}, errors.New("open managed policy revision ledger")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return policyRevisionLedger{}, errors.New("inspect opened policy revision ledger")
	}
	if !openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm() != 0o600 ||
		!os.SameFile(initialInfo, openedInfo) {
		return policyRevisionLedger{}, errors.New(
			"managed policy revision ledger changed while opening it",
		)
	}
	if openedInfo.Size() > maxPolicyRevisionLedgerBytes {
		return policyRevisionLedger{}, errors.New(
			"managed policy revision ledger exceeds its size limit",
		)
	}
	var ledger policyRevisionLedger
	if err := decodeStrict(
		io.LimitReader(file, maxPolicyRevisionLedgerBytes+1),
		&ledger,
	); err != nil {
		return policyRevisionLedger{}, errors.New("decode managed policy revision ledger")
	}
	if err := ledger.validate(); err != nil {
		return policyRevisionLedger{}, err
	}
	return ledger, nil
}

func persistPolicyRevisionLedger(
	parent string,
	path string,
	ledger policyRevisionLedger,
) error {
	if err := ledger.validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(ledger)
	if err != nil || len(encoded) > maxPolicyRevisionLedgerBytes {
		return errors.New("encode managed policy revision ledger")
	}
	encoded = append(encoded, '\n')
	temporary, err := writeTemporaryPolicy(parent, encoded)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.Link(temporary, path); err != nil {
			return errors.New("install managed policy revision ledger")
		}
	} else if err != nil {
		return errors.New("inspect managed policy revision ledger destination")
	} else if err := os.Rename(temporary, path); err != nil {
		return errors.New("replace managed policy revision ledger")
	}
	return syncDirectory(parent)
}

func (ledger policyRevisionLedger) validate() error {
	if ledger.Schema != policyRevisionLedgerSchema ||
		ledger.SchemaVersion != policyRevisionLedgerVersion ||
		len(ledger.Policies) > maxRememberedPolicyIDs {
		return errors.New("managed policy revision ledger is invalid")
	}
	seen := make(map[string]struct{}, len(ledger.Policies))
	for _, entry := range ledger.Policies {
		decodedDigest, digestErr := hex.DecodeString(entry.DocumentSHA256)
		if !safeIdentifier(entry.PolicyID, 128) ||
			entry.HighestRevision == 0 ||
			digestErr != nil ||
			len(decodedDigest) != sha256.Size {
			return errors.New("managed policy revision ledger is invalid")
		}
		if _, exists := seen[entry.PolicyID]; exists {
			return errors.New("managed policy revision ledger contains duplicate policy ids")
		}
		seen[entry.PolicyID] = struct{}{}
	}
	return nil
}

func (ledger *policyRevisionLedger) observe(
	document controller.PolicyDocument,
) (bool, error) {
	digest, err := policyDocumentDigest(document)
	if err != nil {
		return false, err
	}
	for index := range ledger.Policies {
		entry := &ledger.Policies[index]
		if entry.PolicyID != document.ID {
			continue
		}
		switch {
		case document.Revision < entry.HighestRevision:
			return false, errors.New("managed policy revision rollback rejected")
		case document.Revision == entry.HighestRevision &&
			digest != entry.DocumentSHA256:
			return false, errors.New("managed policy revision equivocation rejected")
		case document.Revision == entry.HighestRevision:
			return false, nil
		default:
			entry.HighestRevision = document.Revision
			entry.DocumentSHA256 = digest
			return true, nil
		}
	}
	if len(ledger.Policies) >= maxRememberedPolicyIDs {
		return false, errors.New("managed policy revision ledger is full")
	}
	ledger.Policies = append(ledger.Policies, policyRevisionEntry{
		PolicyID:        document.ID,
		HighestRevision: document.Revision,
		DocumentSHA256:  digest,
	})
	sort.Slice(ledger.Policies, func(left, right int) bool {
		return ledger.Policies[left].PolicyID < ledger.Policies[right].PolicyID
	})
	return true, nil
}

func (ledger policyRevisionLedger) verifyCurrent(
	document controller.PolicyDocument,
) error {
	digest, err := policyDocumentDigest(document)
	if err != nil {
		return err
	}
	for _, entry := range ledger.Policies {
		if entry.PolicyID != document.ID {
			continue
		}
		if entry.HighestRevision != document.Revision ||
			entry.DocumentSHA256 != digest {
			return errors.New("cached managed policy does not match revision ledger")
		}
		return nil
	}
	return errors.New("cached managed policy is absent from revision ledger")
}

func policyDocumentDigest(document controller.PolicyDocument) (string, error) {
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", errors.New("encode managed policy revision digest")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func verifyPinnedPolicy(
	pinnedEncoding string,
	signed controller.SignedPolicy,
) error {
	pinned, err := decodePublicKey(pinnedEncoding)
	if err != nil {
		return errors.New("pinned policy public key is invalid")
	}
	presented, err := decodePublicKey(signed.SigningPublicKey)
	if err != nil ||
		subtle.ConstantTimeCompare(pinned, presented) != 1 {
		return errors.New("policy signer does not match pinned key")
	}
	if err := controller.VerifySignedPolicy(signed); err != nil {
		return errors.New("controller policy signature is invalid")
	}
	return nil
}

func policiesEqual(
	left controller.PolicyDocument,
	right controller.PolicyDocument,
) (bool, error) {
	leftJSON, err := json.Marshal(left)
	if err != nil {
		return false, errors.New("encode existing managed policy")
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		return false, errors.New("encode presented managed policy")
	}
	return bytes.Equal(leftJSON, rightJSON), nil
}

func writeTemporaryPolicy(parent string, encoded []byte) (string, error) {
	file, err := os.CreateTemp(parent, ".managed-policy-*")
	if err != nil {
		return "", errors.New("create temporary managed policy")
	}
	name := file.Name()
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(name)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return "", errors.New("restrict temporary managed policy")
	}
	if _, err := file.Write(encoded); err != nil {
		cleanup()
		return "", errors.New("write managed policy")
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", errors.New("sync managed policy")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", errors.New("close managed policy")
	}
	return name, nil
}

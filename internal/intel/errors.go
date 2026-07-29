package intel

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidEncoding     = errors.New("intel: invalid canonical JSON encoding")
	ErrNonCanonical        = errors.New("intel: bundle is not canonical JSON")
	ErrBundleTooLarge      = errors.New("intel: bundle exceeds size limit")
	ErrTooManyRecords      = errors.New("intel: bundle exceeds record limit")
	ErrInvalidBundle       = errors.New("intel: invalid bundle envelope")
	ErrInvalidRecord       = errors.New("intel: invalid declarative record")
	ErrDuplicateRecord     = errors.New("intel: duplicate record")
	ErrPayloadHashMismatch = errors.New("intel: payload hash mismatch")
	ErrUnknownKey          = errors.New("intel: signing key is not trusted")
	ErrInvalidSignature    = errors.New("intel: signature verification failed")
	ErrExpired             = errors.New("intel: bundle has expired")
	ErrNotYetValid         = errors.New("intel: bundle is not yet valid")
	ErrAgentSchema         = errors.New("intel: agent schema is below bundle minimum")
	ErrRollback            = errors.New("intel: bundle sequence would roll back accepted state")
	ErrSequenceConflict    = errors.New("intel: accepted sequence conflicts with different content")
	ErrInvalidTrustStore   = errors.New("intel: invalid trust store")
	ErrInsecurePermissions = errors.New("intel: file permissions must be 0600")
	ErrUnsafeFile          = errors.New("intel: expected a regular non-symlink file")
	ErrNoCurrentBundle     = errors.New("intel: no current bundle is installed")
	ErrCurrentState        = errors.New("intel: invalid current bundle metadata")
)

type recordValidationError struct {
	index int
	code  string
	cause error
}

func (e *recordValidationError) Error() string {
	return fmt.Sprintf("intel: record %d failed validation (%s)", e.index, e.code)
}

func (e *recordValidationError) Unwrap() error {
	return e.cause
}

func invalidRecord(index int, code string) error {
	return &recordValidationError{index: index, code: code, cause: ErrInvalidRecord}
}

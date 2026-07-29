package intel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

const (
	currentFileName         = "current.json"
	bundlesDirectoryName    = "bundles"
	maxCurrentMetadataBytes = 64 << 10
	maxCurrentReadAttempts  = 128
)

var (
	bundleFilePattern = regexp.MustCompile(`^bundle-([0-9a-f]{64})\.json$`)
	installLocks      sync.Map
)

// Install verifies and atomically publishes a bundle. Immutable bundle content
// is written first; current.json is the final atomic commit pointer.
func Install(
	ctx context.Context,
	encoded []byte,
	trustStore *TrustStore,
	directory string,
	options InstallOptions,
) (InstallResult, error) {
	if err := ctx.Err(); err != nil {
		return InstallResult{}, err
	}
	if directory == "" {
		return InstallResult{}, errors.New("intel: invalid install directory")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil || absolute == "" {
		return InstallResult{}, errors.New("intel: invalid install directory")
	}
	lock := directoryLock(absolute)
	lock.Lock()
	defer lock.Unlock()

	if err := ensurePrivateDirectory(absolute); err != nil {
		return InstallResult{}, err
	}
	bundlesDirectory := filepath.Join(absolute, bundlesDirectoryName)
	if err := ensurePrivateDirectory(bundlesDirectory); err != nil {
		return InstallResult{}, err
	}

	verifyOptions := options.Verify
	currentMetadata, currentBytes, currentErr := ReadCurrent(absolute, verifyOptions.Limits)
	switch {
	case currentErr == nil:
		currentState := currentMetadata.AcceptanceState()
		effective, err := strongerAcceptance(verifyOptions.LastAccepted, &currentState)
		if err != nil {
			return InstallResult{}, err
		}
		verifyOptions.LastAccepted = effective
	case errors.Is(currentErr, ErrNoCurrentBundle):
	default:
		return InstallResult{}, currentErr
	}

	verified, err := Verify(encoded, trustStore, verifyOptions)
	if err != nil {
		return InstallResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return InstallResult{}, err
	}

	bundleHash := hashBytes(verified.Canonical)
	bundleFile := "bundle-" + bundleHash + ".json"
	metadata := CurrentMetadata{
		Schema:        CurrentSchema,
		SchemaVersion: CurrentSchemaVersion,
		BundleFile:    bundleFile,
		BundleID:      verified.Bundle.BundleID,
		Sequence:      verified.Bundle.Sequence,
		PayloadSHA256: verified.Bundle.PayloadSHA256,
		BundleSHA256:  bundleHash,
		KeyID:         verified.Bundle.KeyID,
	}

	if currentErr == nil &&
		verified.Replay &&
		currentMetadata == metadata &&
		bytes.Equal(currentBytes, verified.Canonical) {
		return InstallResult{Metadata: metadata, Installed: false, Replay: true}, nil
	}

	bundlePath := filepath.Join(bundlesDirectory, bundleFile)
	if err := writeImmutableFile(ctx, bundlePath, verified.Canonical); err != nil {
		return InstallResult{}, err
	}
	currentJSON, err := jsonMarshal(metadata)
	if err != nil {
		return InstallResult{}, ErrCurrentState
	}
	if err := writeAtomicFile(ctx, filepath.Join(absolute, currentFileName), currentJSON); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{
		Metadata:  metadata,
		Installed: true,
		Replay:    verified.Replay,
	}, nil
}

// ReadCurrent follows the atomically published current pointer and validates
// both file permissions and the content-addressed immutable bundle. It does not
// establish signer trust; callers must Verify the returned bytes before use.
func ReadCurrent(directory string, limits Limits) (CurrentMetadata, []byte, error) {
	resolvedLimits, err := normalizeLimits(limits)
	if err != nil {
		return CurrentMetadata{}, nil, err
	}
	if err := inspectPrivateDirectory(directory); err != nil {
		if isNotExist(err) {
			return CurrentMetadata{}, nil, ErrNoCurrentBundle
		}
		return CurrentMetadata{}, nil, err
	}
	if err := inspectPrivateDirectory(filepath.Join(directory, bundlesDirectoryName)); err != nil {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	currentPath := filepath.Join(directory, currentFileName)
	var currentJSON []byte
	for attempt := 0; attempt < maxCurrentReadAttempts; attempt++ {
		currentJSON, err = readSecureRegularFile(currentPath, maxCurrentMetadataBytes)
		if !errors.Is(err, errFileChanged) {
			break
		}
	}
	if errors.Is(err, os.ErrNotExist) {
		return CurrentMetadata{}, nil, ErrNoCurrentBundle
	}
	if err != nil {
		var pathError *os.PathError
		if errors.As(err, &pathError) && errors.Is(pathError.Err, os.ErrNotExist) {
			return CurrentMetadata{}, nil, ErrNoCurrentBundle
		}
		if errors.Is(err, errFileChanged) {
			return CurrentMetadata{}, nil, ErrCurrentState
		}
		return CurrentMetadata{}, nil, err
	}

	var metadata CurrentMetadata
	if err := decodeStrict(currentJSON, &metadata); err != nil ||
		!validCurrentMetadata(metadata) {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	bundlePath := filepath.Join(directory, bundlesDirectoryName, metadata.BundleFile)
	bundleJSON, err := readSecureRegularFile(bundlePath, resolvedLimits.MaxBundleBytes)
	if err != nil {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	if hashBytes(bundleJSON) != metadata.BundleSHA256 {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	var bundle Bundle
	if err := decodeStrict(bundleJSON, &bundle); err != nil {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	prepared, _, err := prepareBundle(bundle, resolvedLimits)
	if err != nil {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	canonical, err := canonicalBundle(prepared)
	if err != nil ||
		!bytes.Equal(canonical, bundleJSON) ||
		bundle.BundleID != metadata.BundleID ||
		bundle.Sequence != metadata.Sequence ||
		bundle.PayloadSHA256 != metadata.PayloadSHA256 ||
		bundle.KeyID != metadata.KeyID {
		return CurrentMetadata{}, nil, ErrCurrentState
	}
	return metadata, bundleJSON, nil
}

func validCurrentMetadata(metadata CurrentMetadata) bool {
	match := bundleFilePattern.FindStringSubmatch(metadata.BundleFile)
	return metadata.Schema == CurrentSchema &&
		metadata.SchemaVersion == CurrentSchemaVersion &&
		len(match) == 2 &&
		match[1] == metadata.BundleSHA256 &&
		boundedIdentifier(metadata.BundleID, maxBundleIDBytes) &&
		metadata.Sequence > 0 &&
		sha256Pattern.MatchString(metadata.PayloadSHA256) &&
		boundedIdentifier(metadata.KeyID, maxKeyIDBytes)
}

func strongerAcceptance(
	caller *AcceptanceState,
	current *AcceptanceState,
) (*AcceptanceState, error) {
	if caller == nil || caller.Sequence == 0 {
		copy := *current
		return &copy, nil
	}
	if current == nil || current.Sequence == 0 {
		copy := *caller
		return &copy, nil
	}
	switch {
	case caller.Sequence > current.Sequence:
		copy := *caller
		return &copy, nil
	case current.Sequence > caller.Sequence:
		copy := *current
		return &copy, nil
	case caller.BundleID != current.BundleID ||
		caller.PayloadSHA256 != current.PayloadSHA256:
		return nil, ErrSequenceConflict
	default:
		copy := *current
		return &copy, nil
	}
}

func directoryLock(directory string) *sync.Mutex {
	value, _ := installLocks.LoadOrStore(directory, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func ensurePrivateDirectory(path string) error {
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("intel: create private directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("intel: restrict private directory: %w", err)
		}
		return ensurePrivateDirectory(path)
	case err != nil:
		return fmt.Errorf("intel: inspect private directory: %w", err)
	default:
		return inspectPrivateDirectory(path)
	}
}

func inspectPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err != nil:
		return fmt.Errorf("intel: inspect private directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.IsDir():
		return ErrUnsafeFile
	case info.Mode().Perm() != 0o700:
		return errors.New("intel: directory permissions must be 0700")
	default:
		return nil
	}
}

func writeImmutableFile(ctx context.Context, path string, content []byte) error {
	existing, err := readSecureRegularFile(path, int64(len(content)))
	switch {
	case err == nil:
		if !bytes.Equal(existing, content) {
			return ErrCurrentState
		}
		return nil
	case errors.Is(err, os.ErrNotExist):
	case isNotExist(err):
	default:
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".bundle-*.tmp")
	if err != nil {
		return fmt.Errorf("intel: create bundle temp file: %w", err)
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("intel: restrict bundle temp file: %w", err)
	}
	if err := writeAndSync(ctx, temp, content); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("intel: close bundle temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		if existing, readErr := readSecureRegularFile(path, int64(len(content))); readErr == nil &&
			bytes.Equal(existing, content) {
			return nil
		}
		return fmt.Errorf("intel: publish immutable bundle: %w", err)
	}
	cleanup = false
	return syncDirectory(filepath.Dir(path))
}

func writeAtomicFile(ctx context.Context, path string, content []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".current-*.tmp")
	if err != nil {
		return fmt.Errorf("intel: create current temp file: %w", err)
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("intel: restrict current temp file: %w", err)
	}
	if err := writeAndSync(ctx, temp, content); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("intel: close current temp file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("intel: publish current metadata: %w", err)
	}
	cleanup = false
	return syncDirectory(filepath.Dir(path))
}

func writeAndSync(ctx context.Context, file *os.File, content []byte) error {
	const chunkSize = 64 << 10
	for offset := 0; offset < len(content); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := offset + chunkSize
		if end > len(content) {
			end = len(content)
		}
		count, err := file.Write(content[offset:end])
		if err != nil {
			return fmt.Errorf("intel: write local file: %w", err)
		}
		if count == 0 {
			return fmt.Errorf("intel: write local file: %w", io.ErrShortWrite)
		}
		offset += count
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("intel: sync local file: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("intel: open directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("intel: sync directory: %w", err)
	}
	return nil
}

func isNotExist(err error) bool {
	var pathError *os.PathError
	return errors.As(err, &pathError) && errors.Is(pathError.Err, os.ErrNotExist)
}

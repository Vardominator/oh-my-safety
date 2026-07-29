package intel

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInstallAtomicPermissionsAndReplay(t *testing.T) {
	publicKey, privateKey := testKey(11)
	_, encoded := signTestBundle(t, testBundle(20), privateKey)
	directory := filepath.Join(t.TempDir(), "intelligence")
	options := InstallOptions{Verify: VerifyOptions{Now: testClock, AgentSchema: 1}}

	result, err := Install(context.Background(), encoded, testTrust(publicKey), directory, options)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if !result.Installed || result.Replay {
		t.Fatalf("first install result = %+v", result)
	}

	assertMode(t, directory, 0o700)
	assertMode(t, filepath.Join(directory, bundlesDirectoryName), 0o700)
	assertMode(t, filepath.Join(directory, currentFileName), 0o600)
	bundlePath := filepath.Join(directory, bundlesDirectoryName, result.Metadata.BundleFile)
	assertMode(t, bundlePath, 0o600)

	metadata, current, err := ReadCurrent(directory, Limits{})
	if err != nil {
		t.Fatalf("ReadCurrent() error = %v", err)
	}
	if metadata != result.Metadata || !bytes.Equal(current, encoded) {
		t.Fatal("current pointer did not resolve to installed canonical bundle")
	}
	verifyTestBundle(t, current, testTrust(publicKey))

	replay, err := Install(context.Background(), encoded, testTrust(publicKey), directory, options)
	if err != nil {
		t.Fatalf("replay Install() error = %v", err)
	}
	if replay.Installed || !replay.Replay || replay.Metadata != metadata {
		t.Fatalf("replay result = %+v", replay)
	}

	_, older := signTestBundle(t, testBundle(19), privateKey)
	if _, err := Install(context.Background(), older, testTrust(publicKey), directory, options); !errors.Is(err, ErrRollback) {
		t.Fatalf("older Install() error = %v, want rollback", err)
	}
}

func TestInstallRejectsInsecureDirectoryAndCancelledContext(t *testing.T) {
	publicKey, privateKey := testKey(12)
	_, encoded := signTestBundle(t, testBundle(21), privateKey)

	insecure := filepath.Join(t.TempDir(), "insecure")
	if err := os.Mkdir(insecure, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(
		context.Background(),
		encoded,
		testTrust(publicKey),
		insecure,
		InstallOptions{Verify: VerifyOptions{Now: testClock}},
	); err == nil {
		t.Fatal("Install() accepted an insecure directory")
	}

	cancelled := filepath.Join(t.TempDir(), "cancelled")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Install(
		ctx,
		encoded,
		testTrust(publicKey),
		cancelled,
		InstallOptions{Verify: VerifyOptions{Now: testClock}},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Install() error = %v", err)
	}
	if _, err := os.Lstat(cancelled); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled install created state: %v", err)
	}
}

func TestInstallAndReadCurrentRejectSymlinkedStateRoot(t *testing.T) {
	publicKey, privateKey := testKey(16)
	_, encoded := signTestBundle(t, testBundle(23), privateKey)
	parent := t.TempDir()
	directory := filepath.Join(parent, "intelligence")
	options := InstallOptions{Verify: VerifyOptions{Now: testClock}}
	if _, err := Install(
		context.Background(),
		encoded,
		testTrust(publicKey),
		directory,
		options,
	); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "intelligence-link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCurrent(link, Limits{}); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("ReadCurrent(symlink root) error = %v", err)
	}
	if _, err := Install(
		context.Background(),
		encoded,
		testTrust(publicKey),
		link,
		options,
	); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("Install(symlink root) error = %v", err)
	}
}

func TestReadCurrentRejectsMetadataMismatch(t *testing.T) {
	publicKey, privateKey := testKey(13)
	_, encoded := signTestBundle(t, testBundle(22), privateKey)
	directory := filepath.Join(t.TempDir(), "intelligence")
	result, err := Install(
		context.Background(),
		encoded,
		testTrust(publicKey),
		directory,
		InstallOptions{Verify: VerifyOptions{Now: testClock}},
	)
	if err != nil {
		t.Fatal(err)
	}

	metadata := result.Metadata
	metadata.Sequence++
	encodedMetadata, err := jsonMarshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, currentFileName), encodedMetadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadCurrent(directory, Limits{}); !errors.Is(err, ErrCurrentState) {
		t.Fatalf("ReadCurrent() error = %v, want invalid current state", err)
	}
}

func TestConcurrentReadersObserveOnlyCompleteInstalls(t *testing.T) {
	publicKey, privateKey := testKey(14)
	trust := testTrust(publicKey)
	directory := filepath.Join(t.TempDir(), "intelligence")
	options := InstallOptions{Verify: VerifyOptions{Now: testClock}}
	_, initial := signTestBundle(t, testBundle(30), privateKey)
	if _, err := Install(context.Background(), initial, trust, directory, options); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var failureMu sync.Mutex
	var readerFailure error
	var readers sync.WaitGroup
	for index := 0; index < 4; index++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				metadata, encoded, err := ReadCurrent(directory, Limits{})
				if err != nil {
					failureMu.Lock()
					if readerFailure == nil {
						readerFailure = err
					}
					failureMu.Unlock()
					return
				}
				verified, err := Verify(encoded, trust, VerifyOptions{Now: testClock})
				if err != nil ||
					verified.Bundle.Sequence != metadata.Sequence ||
					verified.Bundle.PayloadSHA256 != metadata.PayloadSHA256 {
					if err == nil {
						err = ErrCurrentState
					}
					failureMu.Lock()
					if readerFailure == nil {
						readerFailure = err
					}
					failureMu.Unlock()
					return
				}
			}
		}()
	}

	for sequence := uint64(31); sequence <= 45; sequence++ {
		bundle := testBundle(sequence)
		bundle.BundleID = "stable"
		_, encoded := signTestBundle(t, bundle, privateKey)
		if _, err := Install(context.Background(), encoded, trust, directory, options); err != nil {
			stop.Store(true)
			readers.Wait()
			t.Fatalf("Install(sequence=%d) error = %v", sequence, err)
		}
	}
	stop.Store(true)
	readers.Wait()
	if readerFailure != nil {
		t.Fatalf("concurrent reader observed partial state: %v", readerFailure)
	}
	metadata, _, err := ReadCurrent(directory, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Sequence != 45 {
		t.Fatalf("final sequence = %d, want 45", metadata.Sequence)
	}
}

func TestConcurrentInstallersPreserveHighestSequence(t *testing.T) {
	publicKey, privateKey := testKey(15)
	trust := testTrust(publicKey)
	directory := filepath.Join(t.TempDir(), "intelligence")
	options := InstallOptions{Verify: VerifyOptions{Now: testClock}}

	encodedBySequence := make(map[uint64][]byte)
	for sequence := uint64(50); sequence < 58; sequence++ {
		_, encoded := signTestBundle(t, testBundle(sequence), privateKey)
		encodedBySequence[sequence] = encoded
	}
	var installers sync.WaitGroup
	failures := make(chan error, 8)
	for sequence := uint64(50); sequence < 58; sequence++ {
		sequence := sequence
		installers.Add(1)
		go func() {
			defer installers.Done()
			_, err := Install(
				context.Background(),
				encodedBySequence[sequence],
				trust,
				directory,
				options,
			)
			if err != nil && !errors.Is(err, ErrRollback) {
				failures <- err
			}
		}()
	}
	installers.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent Install() error = %v", err)
	}

	metadata, _, err := ReadCurrent(directory, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Sequence != 57 {
		t.Fatalf("final sequence = %d, want 57", metadata.Sequence)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", filepath.Base(path), got, want)
	}
}

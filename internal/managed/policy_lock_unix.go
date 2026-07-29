//go:build darwin || linux

package managed

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func acquirePolicyWriteLock(parent string) (func(), error) {
	path := filepath.Join(parent, ".managed-policy.lock")
	descriptor, err := syscall.Open(
		path,
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return nil, errors.New("open managed policy lock")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("open managed policy lock")
	}
	fail := func(message string) (func(), error) {
		_ = file.Close()
		return nil, errors.New(message)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		return fail("inspect managed policy lock")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil ||
		!openedInfo.Mode().IsRegular() ||
		openedInfo.Mode().Perm() != 0o600 ||
		!pathInfo.Mode().IsRegular() ||
		pathInfo.Mode().Perm() != 0o600 ||
		!os.SameFile(openedInfo, pathInfo) {
		return fail("managed policy lock is unsafe")
	}
	if err := syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail("another managed policy update is in progress")
	}
	release := func() {
		_ = syscall.Flock(descriptor, syscall.LOCK_UN)
		_ = file.Close()
	}
	return release, nil
}

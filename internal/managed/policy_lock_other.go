//go:build !darwin && !linux

package managed

import "errors"

func acquirePolicyWriteLock(_ string) (func(), error) {
	return nil, errors.New("managed policy locking is unsupported on this platform")
}

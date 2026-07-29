//go:build !darwin && !linux

package scanner

import "os"

func ownershipFromFileInfo(os.FileInfo) FileOwnership {
	return FileOwnership{}
}

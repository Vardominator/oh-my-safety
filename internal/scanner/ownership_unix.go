//go:build darwin || linux

package scanner

import (
	"os"
	"syscall"
)

func ownershipFromFileInfo(info os.FileInfo) FileOwnership {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileOwnership{}
	}
	return FileOwnership{
		Known: true,
		UID:   stat.Uid,
		GID:   stat.Gid,
	}
}

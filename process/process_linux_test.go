//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"
)

func TestCheckInodeDeviceMapping(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "mapped-object")
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, file.Truncate(1))

	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(int(file.Fd()), &stat))
	mapping := &RawMapping{Path: file.Name(), Device: stat.Dev, Inode: stat.Ino}
	require.NoError(t, checkInodeDeviceMapping(file, mapping))

	mapping.Inode++
	require.ErrorContains(t, checkInodeDeviceMapping(file, mapping), "inode/device mismatch")
}

func mapTestFile(t *testing.T, contents byte) ([]byte, RawMapping) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapped-object")
	data := make([]byte, os.Getpagesize())
	for index := range data {
		data[index] = contents
	}
	require.NoError(t, os.WriteFile(path, data, 0o600))
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	mapped, err := unix.Mmap(int(file.Fd()), 0, len(data), unix.PROT_READ, unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Munmap(mapped)) })
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(int(file.Fd()), &stat))
	proc := New(libpf.PID(os.Getpid()), libpf.PID(os.Getpid()))
	defer proc.Close()
	var mapping RawMapping
	_, err = proc.IterateMappings(func(candidate RawMapping) bool {
		if candidate.Device != stat.Dev || candidate.Inode != stat.Ino {
			return true
		}
		candidate.Path = strings.Clone(candidate.Path)
		mapping = candidate
		return true
	})
	require.NoError(t, err)
	require.NotZero(t, mapping.Inode)
	return mapped, mapping
}

func TestOpenMappingFileUsesMappedInodeAfterPathReplacement(t *testing.T) {
	_, mapping := mapTestFile(t, 'a')
	require.NoError(t, os.Rename(mapping.Path, mapping.Path+".old"))
	require.NoError(t, os.WriteFile(mapping.Path, []byte("replacement"), 0o600))

	proc := New(libpf.PID(os.Getpid()), libpf.PID(os.Getpid()))
	defer proc.Close()
	file, err := proc.OpenMappingFile(&mapping)
	if errors.Is(err, unix.EPERM) {
		t.Skip("kernel restricts /proc/self/map_files; run privileged integration tests")
	}
	require.NoError(t, err)
	defer file.Close()
	contents := make([]byte, 8)
	_, err = file.ReadAt(contents, 0)
	require.NoError(t, err)
	require.Equal(t, []byte("aaaaaaaa"), contents)
}

func TestOpenMappingFileUsesVerifiedCurrentMapping(t *testing.T) {
	_, mapping := mapTestFile(t, 'b')
	proc := New(libpf.PID(os.Getpid()), libpf.PID(os.Getpid()))
	defer proc.Close()
	file, err := proc.OpenMappingFile(&mapping)
	require.NoError(t, err)
	defer file.Close()
	contents := make([]byte, 8)
	_, err = file.ReadAt(contents, 0)
	require.NoError(t, err)
	require.Equal(t, []byte("bbbbbbbb"), contents)
}

func TestOpenMappingFileRejectsStaleMappingBeforeRootFallback(t *testing.T) {
	_, mapping := mapTestFile(t, 'c')
	mapping.Vaddr = 0
	mapping.Length = 1

	proc := New(libpf.PID(os.Getpid()), libpf.PID(os.Getpid()))
	defer proc.Close()
	_, err := proc.OpenMappingFile(&mapping)
	require.ErrorContains(t, err, "mapping is no longer present")
}

func TestOpenInRootPreventsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	require.NoError(t, os.WriteFile(inside, []byte("elf"), 0o600))

	file, err := openInRoot(root, "/inside")
	require.NoError(t, err)
	require.NoError(t, file.Close())

	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("elf"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "escape")))
	_, err = openInRoot(root, "/escape")
	require.Error(t, err)
}

package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Keep untrusted vault files from causing unbounded allocations before JSON
// parsing or password-based key derivation. The limit includes base64 overhead.
const maxVaultFileSize int64 = 64 << 20

// readVaultFile rejects symlinks and non-regular files, and checks the opened
// descriptor against the path inspected before opening it. This prevents
// following a swapped symlink between Lstat and Open.
func readVaultFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("Vault must be a regular file (not a symlink)")
	}
	if before.Size() > maxVaultFileSize {
		return nil, fmt.Errorf("Vault exceeds maximum size of %d bytes", maxVaultFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() > maxVaultFileSize {
		return nil, errors.New("Vault file changed or is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxVaultFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxVaultFileSize {
		return nil, fmt.Errorf("Vault exceeds maximum size of %d bytes", maxVaultFileSize)
	}
	return data, nil
}

// writeVaultFile makes the update visible all at once, including for readers
// that do not acquire the writer lock. It also never follows a symlink at the
// destination and never temporarily truncates the previous ciphertext.
func writeVaultFile(path string, data []byte) error {
	if int64(len(data)) > maxVaultFileSize {
		return fmt.Errorf("Vault exceeds maximum size of %d bytes", maxVaultFileSize)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("Vault must be a regular file (not a symlink)")
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".secrets-vault-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

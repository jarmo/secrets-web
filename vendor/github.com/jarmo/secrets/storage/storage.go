package storage

import (
	"encoding/json"
	"errors"
	"time"
	"os"

	"github.com/jarmo/secrets/crypto"
	"github.com/jarmo/secrets/secret"
	"github.com/juju/fslock"
)

func Read(path string, password []byte) ([]secret.Secret, error) {
	if encryptedSecretsJSON, err := readVaultFile(path); err != nil {
		return nil, err
	} else {
		version, err := vaultVersion(encryptedSecretsJSON)
		if err != nil {
			return nil, err
		}
		if version == 2 {
			var shared crypto.Shared
			if err := json.Unmarshal(encryptedSecretsJSON, &shared); err != nil {
				return nil, err
			}
			return crypto.DecryptShared(password, shared)
		}

		var encryptedSecrets crypto.Encrypted
		if err := json.Unmarshal(encryptedSecretsJSON, &encryptedSecrets); err != nil {
			return nil, err
		}

		if secrets, err := crypto.Decrypt(password, encryptedSecrets); err != nil {
			return secrets, err
		} else {
			return secrets, nil
		}
	}
}

func Write(path string, password []byte, decryptedSecrets []secret.Secret) {
	if fileLock, err := lock(path); err != nil {
		panic(err)
	} else {
		defer fileLock.Unlock()
	}

	encryptedSecretsJSON, err := encryptForStorage(path, password, decryptedSecrets)
	if err != nil {
		panic(err)
	}
	if err := writeVaultFile(path, encryptedSecretsJSON); err != nil {
		panic(err)
	}
}

func lock(path string) (*fslock.Lock, error) {
	// Lock a stable sidecar inode: vault files are replaced atomically by rename.
	// Locking the vault inode itself would no longer serialize later writers.
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("Vault lock must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	lock := fslock.New(lockPath)
	for i := 0; i < 5; i++ {
		err := lock.TryLock()
		if err == nil {
			return lock, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil, errors.New("Failed to lock " + path)
}

package storage

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jarmo/secrets/crypto"
	"github.com/jarmo/secrets/secret"
)

func vaultVersion(data []byte) (int, error) {
	var header struct{ Version int }
	if err := json.Unmarshal(data, &header); err != nil {
		return 0, err
	}
	if header.Version != 0 && header.Version != 2 {
		return 0, fmt.Errorf("Unsupported vault version: %d", header.Version)
	}
	return header.Version, nil
}

func encryptForStorage(path string, password []byte, secrets []secret.Secret) ([]byte, error) {
	existing, err := readVaultFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(existing) == 0 {
		return encryptNewVault(password, secrets)
	}
	version, err := vaultVersion(existing)
	if err != nil {
		return nil, err
	}
	if version == 0 {
		var encrypted crypto.Encrypted
		if err := json.Unmarshal(existing, &encrypted); err != nil {
			return nil, err
		}
		if _, err := crypto.Decrypt(password, encrypted); err != nil {
			return nil, err
		}
		return encryptNewVault(password, secrets)
	}
	var shared crypto.Shared
	if err := json.Unmarshal(existing, &shared); err != nil {
		return nil, err
	}
	updated, err := crypto.ReencryptShared(password, shared, secrets)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(updated, "", "  ")
}

func encryptNewVault(password []byte, secrets []secret.Secret) ([]byte, error) {
	shared, err := crypto.EncryptShared(password, "owner", secrets)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(shared, "", "  ")
}

func Initialize(path string, password []byte) error {
	data, err := encryptNewVault(password, nil)
	if err != nil {
		return err
	}
	return initializeVaultFile(path, data)
}

func initializeVaultFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxVaultFileSize {
		file.Close()
		os.Remove(path)
		return fmt.Errorf("Vault exceeds maximum size of %d bytes", maxVaultFileSize)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}



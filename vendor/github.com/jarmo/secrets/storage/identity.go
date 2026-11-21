package storage

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"

	"github.com/jarmo/secrets/crypto"
	"github.com/jarmo/secrets/secret"
)

func AssociateUser(path string, password []byte, identity crypto.Identity) error {
	if err := requireVault(path); err != nil {
		return err
	}
	fileLock, err := lock(path)
	if err != nil {
		return err
	}
	defer fileLock.Unlock()

	data, err := readVaultFile(path)
	if err != nil {
		return err
	}
	version, err := vaultVersion(data)
	if err != nil {
		return err
	}
	var shared crypto.Shared
	if version == 0 {
		var encrypted crypto.Encrypted
		if err := json.Unmarshal(data, &encrypted); err != nil {
			return err
		}
		secrets, err := crypto.Decrypt(password, encrypted)
		if err != nil {
			return err
		}
		shared, err = crypto.EncryptShared(password, "owner", secrets)
		if err != nil {
			return err
		}
	} else if err := json.Unmarshal(data, &shared); err != nil {
		return err
	}
	updated, err := crypto.AssociateIdentity(password, shared, identity)
	if err != nil {
		return err
	}
	return saveVault(path, updated)
}

func AssociateUserForUser(path string, privateKey *ecdh.PrivateKey, identity crypto.Identity) error {
	if err := requireVault(path); err != nil {
		return err
	}
	fileLock, err := lock(path)
	if err != nil {
		return err
	}
	defer fileLock.Unlock()

	shared, err := loadUserVault(path)
	if err != nil {
		return err
	}
	updated, err := crypto.AssociateIdentityForUser(privateKey, shared, identity)
	if err != nil {
		return err
	}
	return saveVault(path, updated)
}

func CanAccessForUser(path string, privateKey *ecdh.PrivateKey) error {
	shared, err := loadUserVault(path)
	if err != nil {
		return err
	}
	return crypto.CanAccessSharedForUser(privateKey, shared)
}

func ReadForUser(path string, privateKey *ecdh.PrivateKey) ([]secret.Secret, error) {
	shared, err := loadUserVault(path)
	if err != nil {
		return nil, err
	}
	return crypto.DecryptSharedForUser(privateKey, shared)
}

func WriteForUser(path string, privateKey *ecdh.PrivateKey, secrets []secret.Secret) error {
	if err := requireVault(path); err != nil {
		return err
	}
	fileLock, err := lock(path)
	if err != nil {
		return err
	}
	defer fileLock.Unlock()

	shared, err := loadUserVault(path)
	if err != nil {
		return err
	}
	updated, err := crypto.ReencryptSharedForUser(privateKey, shared, secrets)
	if err != nil {
		return err
	}
	return saveVault(path, updated)
}

func loadUserVault(path string) (crypto.Shared, error) {
	data, err := readVaultFile(path)
	if err != nil {
		return crypto.Shared{}, err
	}
	version, err := vaultVersion(data)
	if err != nil {
		return crypto.Shared{}, err
	}
	if version != 2 {
		return crypto.Shared{}, errors.New("Vault must be converted before user access")
	}
	var shared crypto.Shared
	if err := json.Unmarshal(data, &shared); err != nil {
		return crypto.Shared{}, err
	}
	return shared, nil
}

func requireVault(path string) error {
	_, err := readVaultFile(path)
	return err
}

func saveVault(path string, shared crypto.Shared) error {
	data, err := json.MarshalIndent(shared, "", "  ")
	if err != nil {
		return err
	}
	return writeVaultFile(path, data)
}

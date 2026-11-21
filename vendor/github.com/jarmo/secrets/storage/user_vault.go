package storage

import (
	"crypto/ecdh"
	"encoding/json"

	"github.com/jarmo/secrets/crypto"
)

func InitializeForUser(path string, identity crypto.Identity) error {
	shared, err := crypto.EncryptSharedForIdentity(identity, nil)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(shared, "", "  ")
	if err != nil {
		return err
	}
	return initializeVaultFile(path, data)
}

func AssociateUserRetiringPasswords(path, directory string, password []byte, identity crypto.Identity) error {
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
	if version == 0 {
		var encrypted crypto.Encrypted
		if err := json.Unmarshal(data, &encrypted); err != nil {
			return err
		}
		secrets, err := crypto.Decrypt(password, encrypted)
		if err != nil {
			return err
		}
		shared, err := crypto.EncryptSharedForIdentity(identity, secrets)
		if err != nil {
			return err
		}
		return saveRotatedVault(path, shared)
	}
	var shared crypto.Shared
	if err := json.Unmarshal(data, &shared); err != nil {
		return err
	}
	identities, err := loadNamedIdentities(directory)
	if err != nil {
		return err
	}
	updated, err := crypto.AssociateIdentityRetiringPasswords(password, shared, identity, identities)
	if err != nil {
		return err
	}
	return saveRotatedVault(path, updated)
}

func AssociateUserForUserRetiringPasswords(path, directory string, privateKey *ecdh.PrivateKey, identity crypto.Identity) error {
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
	identities, err := loadNamedIdentities(directory)
	if err != nil {
		return err
	}
	updated, err := crypto.AssociateIdentityForUserRetiringPasswords(privateKey, shared, identity, identities)
	if err != nil {
		return err
	}
	return saveRotatedVault(path, updated)
}

package storage

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
	"strings"

	"github.com/jarmo/secrets/crypto"
	"github.com/jarmo/secrets/user"
)

func ListUsers(vaultPath, usersDirectory string, password []byte) ([]crypto.VaultUser, error) {
	shared, err := loadUserVault(vaultPath)
	if err != nil {
		return nil, err
	}
	identities, err := loadNamedIdentities(usersDirectory)
	if err != nil {
		return nil, err
	}
	return crypto.ListSharedUsers(password, shared, identities)
}

func ListUsersForUser(vaultPath, usersDirectory string, privateKey *ecdh.PrivateKey) ([]crypto.VaultUser, error) {
	shared, err := loadUserVault(vaultPath)
	if err != nil {
		return nil, err
	}
	identities, err := loadNamedIdentities(usersDirectory)
	if err != nil {
		return nil, err
	}
	return crypto.ListSharedUsersForUser(privateKey, shared, identities)
}

func RemoveUser(vaultPath, usersDirectory, username string, password []byte) error {
	if err := requireVault(vaultPath); err != nil {
		return err
	}
	fileLock, err := lock(vaultPath)
	if err != nil {
		return err
	}
	defer fileLock.Unlock()

	shared, err := loadUserVault(vaultPath)
	if err != nil {
		return err
	}
	identities, err := loadNamedIdentities(usersDirectory)
	if err != nil {
		return err
	}
	updated, err := crypto.RemoveSharedIdentity(password, shared, username, identities)
	if err != nil {
		return err
	}
	return saveRotatedVault(vaultPath, updated)
}

func RemoveUserForUser(vaultPath, usersDirectory, username string, privateKey *ecdh.PrivateKey) error {
	if err := requireVault(vaultPath); err != nil {
		return err
	}
	fileLock, err := lock(vaultPath)
	if err != nil {
		return err
	}
	defer fileLock.Unlock()

	shared, err := loadUserVault(vaultPath)
	if err != nil {
		return err
	}
	identities, err := loadNamedIdentities(usersDirectory)
	if err != nil {
		return err
	}
	updated, err := crypto.RemoveSharedIdentityForUser(privateKey, shared, username, identities)
	if err != nil {
		return err
	}
	return saveRotatedVault(vaultPath, updated)
}

func RemoveVaultPasswordForUser(vaultPath, usersDirectory string, privateKey *ecdh.PrivateKey) error {
	if err := requireVault(vaultPath); err != nil {
		return err
	}
	fileLock, err := lock(vaultPath)
	if err != nil {
		return err
	}
	defer fileLock.Unlock()

	shared, err := loadUserVault(vaultPath)
	if err != nil {
		return err
	}
	identities, err := loadNamedIdentities(usersDirectory)
	if err != nil {
		return err
	}
	updated, err := crypto.RemoveSharedPasswordsForUser(privateKey, shared, identities)
	if err != nil {
		return err
	}
	return saveRotatedVault(vaultPath, updated)
}

func loadNamedIdentities(directory string) ([]crypto.NamedIdentity, error) {
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	identities := make([]crypto.NamedIdentity, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || strings.HasSuffix(entry.Name(), ".pending.json") {
			continue
		}
		username := strings.TrimSuffix(entry.Name(), ".json")
		record, err := user.Load(directory, username)
		if err != nil {
			return nil, err
		}
		identities = append(identities, crypto.NamedIdentity{Username: username, Identity: record.Identity})
	}
	return identities, nil
}

func saveRotatedVault(path string, shared crypto.Shared) error {
	data, err := json.MarshalIndent(shared, "", "  ")
	if err != nil {
		return err
	}
	return writeVaultFile(path, data)
}

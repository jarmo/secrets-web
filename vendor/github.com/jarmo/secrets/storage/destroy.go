package storage

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jarmo/secrets/user"
)

func DestroyUser(vaultPaths []string, usersDirectory, username string, actingKey *ecdh.PrivateKey) error {
	if len(vaultPaths) == 0 {
		return errors.New("No configured vaults to verify user access against")
	}
	if actingKey == nil {
		return errors.New("User authentication is required")
	}
	record, err := user.Load(usersDirectory, username)
	if err != nil {
		return err
	}
	if record.Identity.PublicKey == base64.StdEncoding.EncodeToString(actingKey.PublicKey().Bytes()) {
		return errors.New("A user cannot destroy their own account")
	}

	var affectedVaults []string
	checked := make(map[string]bool)
	for _, vaultPath := range vaultPaths {
		absolutePath, err := filepath.Abs(vaultPath)
		if err != nil {
			return err
		}
		if checked[absolutePath] {
			continue
		}
		checked[absolutePath] = true
		if err := requireVault(absolutePath); err != nil {
			return fmt.Errorf("Vault %s: %w", absolutePath, err)
		}
		data, err := readVaultFile(absolutePath)
		if err != nil {
			return err
		}
		version, err := vaultVersion(data)
		if err != nil {
			return fmt.Errorf("Vault %s: %w", absolutePath, err)
		}
		if version == 0 {
			continue
		}
		users, err := ListUsersForUser(absolutePath, usersDirectory, actingKey)
		if err != nil {
			return fmt.Errorf("Cannot inspect vault %s: %w", absolutePath, err)
		}
		found := false
		remainingUsers := 0
		for _, vaultUser := range users {
			if vaultUser.PasswordBased {
				continue
			}
			if vaultUser.Name == username {
				found = true
			} else {
				remainingUsers++
			}
		}
		if found {
			if remainingUsers == 0 {
				return fmt.Errorf("Cannot destroy the last user of vault %s", absolutePath)
			}
			affectedVaults = append(affectedVaults, absolutePath)
		}
	}

	for _, vaultPath := range affectedVaults {
		if err := RemoveUserForUser(vaultPath, usersDirectory, username, actingKey); err != nil {
			return fmt.Errorf("Cannot remove user from vault %s: %w", vaultPath, err)
		}
	}
	return user.Destroy(usersDirectory, username)
}

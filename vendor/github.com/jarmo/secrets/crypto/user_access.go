package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type NamedIdentity struct {
	Username string
	Identity Identity
}

type VaultUser struct {
	Name          string
	PasswordBased bool
}

type vaultRecipient struct {
	user    SharedUser
	name      string
	publicKey *ecdh.PublicKey
}

func ListSharedUsers(password []byte, shared Shared, identities []NamedIdentity) ([]VaultUser, error) {
	vaultKey, err := unlockShared(password, shared)
	if err != nil {
		return nil, err
	}
	defer wipeShared(vaultKey[:])
	return listSharedUsers(&vaultKey, shared, identities)
}

func ListSharedUsersForUser(privateKey *ecdh.PrivateKey, shared Shared, identities []NamedIdentity) ([]VaultUser, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return nil, err
	}
	defer wipeShared(vaultKey[:])
	return listSharedUsers(&vaultKey, shared, identities)
}

func listSharedUsers(vaultKey *[32]byte, shared Shared, identities []NamedIdentity) ([]VaultUser, error) {
	if _, err := decryptSharedData(vaultKey, shared); err != nil {
		return nil, err
	}
	recipients, err := resolveVaultRecipients(vaultKey, shared, identities)
	if err != nil {
		return nil, err
	}
	users := make([]VaultUser, 0, len(recipients))
	for _, recipient := range recipients {
		users = append(users, VaultUser{Name: recipient.name, PasswordBased: !isIdentityUser(recipient.user)})
	}
	return users, nil
}

func RemoveSharedIdentity(password []byte, shared Shared, username string, identities []NamedIdentity) (Shared, error) {
	vaultKey, err := unlockShared(password, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	return removeSharedIdentity(&vaultKey, shared, username, identities)
}

func RemoveSharedIdentityForUser(privateKey *ecdh.PrivateKey, shared Shared, username string, identities []NamedIdentity) (Shared, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	return removeSharedIdentity(&vaultKey, shared, username, identities)
}

func removeSharedIdentity(vaultKey *[32]byte, shared Shared, username string, identities []NamedIdentity) (Shared, error) {
	recipients, err := resolveVaultRecipients(vaultKey, shared, identities)
	if err != nil {
		return Shared{}, err
	}
	remaining := make([]vaultRecipient, 0, len(recipients))
	found := false
	for _, recipient := range recipients {
		if isIdentityUser(recipient.user) && recipient.name == username {
			found = true
			continue
		}
		remaining = append(remaining, recipient)
	}
	if !found {
		return Shared{}, errors.New("User does not have access to this vault")
	}
	return rotateSharedRecipients(vaultKey, shared, remaining)
}

func RemoveSharedPasswordsForUser(privateKey *ecdh.PrivateKey, shared Shared, identities []NamedIdentity) (Shared, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	recipients, err := resolveVaultRecipients(&vaultKey, shared, identities)
	if err != nil {
		return Shared{}, err
	}
	remaining := make([]vaultRecipient, 0, len(recipients))
	found := false
	for _, recipient := range recipients {
		if !isIdentityUser(recipient.user) {
			found = true
			continue
		}
		remaining = append(remaining, recipient)
	}
	if !found {
		return Shared{}, errors.New("Vault has no password-based access to remove")
	}
	return rotateSharedRecipients(&vaultKey, shared, remaining)
}

func rotateSharedRecipients(vaultKey *[32]byte, shared Shared, recipients []vaultRecipient) (Shared, error) {
	if len(recipients) == 0 {
		return Shared{}, errors.New("Cannot remove the last vault user")
	}
	secrets, err := decryptSharedData(vaultKey, shared)
	if err != nil {
		return Shared{}, err
	}
	newVaultKey := new([32]byte)
	if _, err := rand.Read(newVaultKey[:]); err != nil {
		return Shared{}, err
	}
	defer wipeShared(newVaultKey[:])
	updated := Shared{Version: shared.Version}
	for _, recipient := range recipients {
		wrapped, err := wrapSharedKey(recipient.publicKey, newVaultKey)
		if err != nil {
			return Shared{}, err
		}
		user := recipient.user
		user.VaultKey = wrapped
		if isIdentityUser(user) {
			user.Name = identityUserName(newVaultKey, recipient.publicKey)
		}
		updated.Users = append(updated.Users, user)
	}
	updated.Data, updated.Nonce, err = encryptSharedData(newVaultKey, secrets)
	if err != nil {
		return Shared{}, err
	}
	return updated, nil
}

func resolveVaultRecipients(vaultKey *[32]byte, shared Shared, identities []NamedIdentity) ([]vaultRecipient, error) {
	known := make(map[string]vaultRecipient, len(identities))
	for _, identity := range identities {
		if err := ValidateIdentity(identity.Identity); err != nil {
			return nil, err
		}
		publicBytes, _ := base64.StdEncoding.DecodeString(identity.Identity.PublicKey)
		publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
		if err != nil {
			return nil, err
		}
		identifier := identityUserName(vaultKey, publicKey)
		if _, exists := known[identifier]; exists {
			return nil, errors.New("Multiple accounts share the same cryptographic identity")
		}
		known[identifier] = vaultRecipient{name: identity.Username, publicKey: publicKey}
	}

	recipients := make([]vaultRecipient, 0, len(shared.Users))
	for _, user := range shared.Users {
		if isIdentityUser(user) {
			identity, found := known[user.Name]
			if !found {
				return nil, errors.New("Cannot resolve all vault users; no changes were made")
			}
			identity.user = user
			recipients = append(recipients, identity)
			continue
		}
		publicBytes, _ := base64.StdEncoding.DecodeString(user.PublicKey)
		publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, vaultRecipient{user: user, name: user.Name, publicKey: publicKey})
	}
	return recipients, nil
}

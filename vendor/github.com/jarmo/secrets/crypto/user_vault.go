package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/jarmo/secrets/secret"
)

func EncryptSharedForIdentity(identity Identity, secrets []secret.Secret) (Shared, error) {
	if err := ValidateIdentity(identity); err != nil {
		return Shared{}, err
	}
	publicBytes, _ := base64.StdEncoding.DecodeString(identity.PublicKey)
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return Shared{}, err
	}
	vaultKey := new([32]byte)
	if _, err := rand.Read(vaultKey[:]); err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	wrapped, err := wrapSharedKey(publicKey, vaultKey)
	if err != nil {
		return Shared{}, err
	}
	data, nonce, err := encryptSharedData(vaultKey, secrets)
	if err != nil {
		return Shared{}, err
	}
	return Shared{Version: 2, Data: data, Nonce: nonce, Users: []SharedUser{{Name: identityUserName(vaultKey, publicKey), VaultKey: wrapped}}}, nil
}

func AssociateIdentityRetiringPasswords(password []byte, shared Shared, identity Identity, identities []NamedIdentity) (Shared, error) {
	vaultKey, err := unlockShared(password, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	return associateIdentityRetiringPasswords(&vaultKey, shared, identity, identities)
}

func AssociateIdentityForUserRetiringPasswords(privateKey *ecdh.PrivateKey, shared Shared, identity Identity, identities []NamedIdentity) (Shared, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	return associateIdentityRetiringPasswords(&vaultKey, shared, identity, identities)
}

func associateIdentityRetiringPasswords(vaultKey *[32]byte, shared Shared, identity Identity, identities []NamedIdentity) (Shared, error) {
	if _, err := decryptSharedData(vaultKey, shared); err != nil {
		return Shared{}, err
	}
	hasPasswordRecipient := false
	for _, recipient := range shared.Users {
		if !isIdentityUser(recipient) {
			hasPasswordRecipient = true
			break
		}
	}
	if err := ValidateIdentity(identity); err != nil {
		return Shared{}, err
	}
	publicBytes, _ := base64.StdEncoding.DecodeString(identity.PublicKey)
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return Shared{}, err
	}
	userName := identityUserName(vaultKey, publicKey)
	alreadyUser := false
	for _, recipient := range shared.Users {
		if recipient.Name == userName {
			alreadyUser = true
			break
		}
	}
	if alreadyUser && !hasPasswordRecipient {
		return Shared{}, errors.New("User already has access to the vault")
	}
	updated := shared
	if !alreadyUser {
		updated, err = addIdentity(shared, vaultKey, identity)
		if err != nil {
			return Shared{}, err
		}
	}
	if !hasPasswordRecipient {
		return updated, nil
	}
	recipients, err := resolveVaultRecipients(vaultKey, updated, identities)
	if err != nil {
		return Shared{}, err
	}
	remaining := make([]vaultRecipient, 0, len(recipients))
	for _, recipient := range recipients {
		if isIdentityUser(recipient.user) {
			remaining = append(remaining, recipient)
		}
	}
	return rotateSharedRecipients(vaultKey, updated, remaining)
}

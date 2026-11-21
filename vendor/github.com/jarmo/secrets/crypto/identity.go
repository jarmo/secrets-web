package crypto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

type Identity struct {
	PublicKey  string
	PrivateKey Encrypted
}

func NewIdentity(password []byte) (Identity, error) {
	if len(password) == 0 {
		return Identity{}, errors.New("A user password is required")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	privateBytes := privateKey.Bytes()
	encrypted, err := encryptSharedPrivateKey(password, privateBytes)
	wipeShared(privateBytes)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		PublicKey:  base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		PrivateKey: encrypted,
	}, nil
}

func ValidateIdentity(identity Identity) error {
	publicKey, err := base64.StdEncoding.DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != 32 {
		return errors.New("Invalid user identity: invalid public key")
	}
	if _, err := ecdh.X25519().NewPublicKey(publicKey); err != nil {
		return errors.New("Invalid user identity: invalid public key")
	}
	if err := validateEncryptedPrivateKey(identity.PrivateKey); err != nil {
		return fmt.Errorf("Invalid user identity: %w", err)
	}
	return nil
}

func UnlockIdentity(password []byte, identity Identity) (*ecdh.PrivateKey, error) {
	if err := ValidateIdentity(identity); err != nil {
		return nil, err
	}
	privateKey, ok := decryptSharedPrivateKey(password, identity.PrivateKey)
	if !ok {
		return nil, errors.New("Invalid user credentials")
	}
	publicKey, _ := base64.StdEncoding.DecodeString(identity.PublicKey)
	if !hmac.Equal(privateKey.PublicKey().Bytes(), publicKey) {
		return nil, errors.New("Invalid user identity: public key does not match private key")
	}
	return privateKey, nil
}

func ChangeIdentityPassword(currentPassword, newPassword []byte, identity Identity) (Identity, error) {
	if len(newPassword) == 0 {
		return Identity{}, errors.New("A user password is required")
	}
	privateKey, err := UnlockIdentity(currentPassword, identity)
	if err != nil {
		return Identity{}, err
	}
	privateBytes := privateKey.Bytes()
	encrypted, err := encryptSharedPrivateKey(newPassword, privateBytes)
	wipeShared(privateBytes)
	if err != nil {
		return Identity{}, err
	}
	identity.PrivateKey = encrypted
	return identity, nil
}

func validateEncryptedPrivateKey(private Encrypted) error {
	if private.Params["Time"] < 1 || private.Params["Time"] > 10 ||
		private.Params["Memory"] < 8 || private.Params["Memory"] > 256*1024 ||
		private.Params["Threads"] < 1 || private.Params["Threads"] > 16 ||
		private.Params["Memory"] < 8*private.Params["Threads"] {
		return errors.New("unsupported Argon2id parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(private.Salt)
	if err != nil || len(salt) != 32 {
		return errors.New("invalid user salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(private.Nonce)
	if err != nil || len(nonce) != 24 {
		return errors.New("invalid user nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(private.Data)
	if err != nil || len(ciphertext) != 32+secretbox.Overhead {
		return errors.New("invalid user private key")
	}
	return nil
}

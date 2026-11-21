package crypto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jarmo/secrets/secret"
	"golang.org/x/crypto/nacl/secretbox"
)

// Shared is the v2 vault format, with a wrapped data key for each user.
type Shared struct {
	Version int
	Data    string
	Nonce   string
	Users   []SharedUser
}

type SharedUser struct {
	Name       string
	PublicKey  string
	PrivateKey Encrypted
	VaultKey   string
}

const maxSharedUsers = 16

// EncryptShared creates a v2 vault with one password-protected user.
func EncryptShared(password []byte, userName string, secrets []secret.Secret) (Shared, error) {
	if len(password) == 0 {
		return Shared{}, errors.New("A user password is required")
	}
	if strings.TrimSpace(userName) == "" || len(userName) > 64 {
		return Shared{}, errors.New("A user name (up to 64 bytes) is required")
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Shared{}, err
	}
	vaultKey := new([32]byte)
	if _, err := rand.Read(vaultKey[:]); err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])

	wrapped, err := wrapSharedKey(privateKey.PublicKey(), vaultKey)
	if err != nil {
		return Shared{}, err
	}
	privateBytes := privateKey.Bytes()
	private, err := encryptSharedPrivateKey(password, privateBytes)
	wipeShared(privateBytes)
	if err != nil {
		return Shared{}, err
	}
	data, nonce, err := encryptSharedData(vaultKey, secrets)
	if err != nil {
		return Shared{}, err
	}
	user := SharedUser{
		Name:       userName,
		PublicKey:  base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		PrivateKey: private,
		VaultKey:   wrapped,
	}
	return Shared{Version: 2, Data: data, Nonce: nonce, Users: []SharedUser{user}}, nil
}

func DecryptShared(password []byte, shared Shared) ([]secret.Secret, error) {
	vaultKey, err := unlockShared(password, shared)
	if err != nil {
		return nil, err
	}
	defer wipeShared(vaultKey[:])
	return decryptSharedData(&vaultKey, shared)
}

func AssociateIdentity(password []byte, shared Shared, identity Identity) (Shared, error) {
	vaultKey, err := unlockShared(password, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	if _, err := decryptSharedData(&vaultKey, shared); err != nil {
		return Shared{}, err
	}
	return addIdentity(shared, &vaultKey, identity)
}

func AssociateIdentityForUser(privateKey *ecdh.PrivateKey, shared Shared, identity Identity) (Shared, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	if _, err := decryptSharedData(&vaultKey, shared); err != nil {
		return Shared{}, err
	}
	return addIdentity(shared, &vaultKey, identity)
}

func CanAccessSharedForUser(privateKey *ecdh.PrivateKey, shared Shared) error {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return err
	}
	wipeShared(vaultKey[:])
	return nil
}

func DecryptSharedForUser(privateKey *ecdh.PrivateKey, shared Shared) ([]secret.Secret, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return nil, err
	}
	defer wipeShared(vaultKey[:])
	return decryptSharedData(&vaultKey, shared)
}

func ReencryptSharedForUser(privateKey *ecdh.PrivateKey, shared Shared, secrets []secret.Secret) (Shared, error) {
	vaultKey, err := unlockIdentity(privateKey, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	if _, err := decryptSharedData(&vaultKey, shared); err != nil {
		return Shared{}, err
	}
	shared.Data, shared.Nonce, err = encryptSharedData(&vaultKey, secrets)
	return shared, err
}

func addIdentity(shared Shared, vaultKey *[32]byte, identity Identity) (Shared, error) {
	if err := ValidateIdentity(identity); err != nil {
		return Shared{}, err
	}
	if len(shared.Users) >= maxSharedUsers {
		return Shared{}, errors.New("Vault user limit reached")
	}
	publicBytes, _ := base64.StdEncoding.DecodeString(identity.PublicKey)
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return Shared{}, err
	}
	name := identityUserName(vaultKey, publicKey)
	for _, existing := range shared.Users {
		if existing.Name == name {
			return Shared{}, errors.New("User already has access to the vault")
		}
	}
	wrapped, err := wrapSharedKey(publicKey, vaultKey)
	if err != nil {
		return Shared{}, err
	}
	shared.Users = append(shared.Users, SharedUser{Name: name, VaultKey: wrapped})
	return shared, nil
}

func identityUserName(vaultKey *[32]byte, publicKey *ecdh.PublicKey) string {
	mac := hmac.New(sha256.New, vaultKey[:])
	mac.Write([]byte("secrets-v2-identity-user"))
	mac.Write(publicKey.Bytes())
	return "user-" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func unlockIdentity(privateKey *ecdh.PrivateKey, shared Shared) ([32]byte, error) {
	if privateKey == nil {
		return [32]byte{}, errors.New("User key is required")
	}
	if err := validateShared(shared); err != nil {
		return [32]byte{}, err
	}
	for _, user := range shared.Users {
		if !isIdentityUser(user) {
			continue
		}
		vaultKey, err := unwrapSharedKey(privateKey, user.VaultKey)
		if err != nil {
			continue
		}
		if user.Name == identityUserName(&vaultKey, privateKey.PublicKey()) {
			return vaultKey, nil
		}
		wipeShared(vaultKey[:])
	}
	return [32]byte{}, errors.New("User cannot access this vault")
}

func isIdentityUser(user SharedUser) bool {
	return user.PublicKey == "" && strings.HasPrefix(user.Name, "user-")
}

// ReencryptShared retains user credentials when the vault contents change.
func ReencryptShared(password []byte, shared Shared, secrets []secret.Secret) (Shared, error) {
	vaultKey, err := unlockShared(password, shared)
	if err != nil {
		return Shared{}, err
	}
	defer wipeShared(vaultKey[:])
	// Do not overwrite a damaged vault without authenticating its old contents.
	if _, err := decryptSharedData(&vaultKey, shared); err != nil {
		return Shared{}, err
	}
	data, nonce, err := encryptSharedData(&vaultKey, secrets)
	if err != nil {
		return Shared{}, err
	}
	shared.Data = data
	shared.Nonce = nonce
	return shared, nil
}

func encryptSharedData(key *[32]byte, secrets []secret.Secret) (string, string, error) {
	plain, err := json.Marshal(secrets)
	if err != nil {
		return "", "", err
	}
	defer wipeShared(plain)
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", err
	}
	ciphertext := secretbox.Seal(nil, plain, &nonce, key)
	return base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce[:]), nil
}

func decryptSharedData(key *[32]byte, shared Shared) ([]secret.Secret, error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(shared.Data)
	nonceBytes, _ := base64.StdEncoding.DecodeString(shared.Nonce)
	var nonce [24]byte
	copy(nonce[:], nonceBytes)
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, key)
	if !ok {
		return nil, errors.New("Invalid vault format: vault ciphertext authentication failed")
	}
	defer wipeShared(plaintext)
	var secrets []secret.Secret
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("Invalid vault format: invalid decrypted secrets: %w", err)
	}
	return secrets, nil
}

func encryptSharedPrivateKey(password, privateKey []byte) (Encrypted, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return Encrypted{}, err
	}
	params := map[string]int{"Time": 3, "Memory": 64 * 1024, "Threads": 4}
	key := secretKey(password, salt, params)
	defer wipeShared(key[:])
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Encrypted{}, err
	}
	ciphertext := secretbox.Seal(nil, privateKey, &nonce, &key)
	return Encrypted{
		Data:   base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:  base64.StdEncoding.EncodeToString(nonce[:]),
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Params: params,
	}, nil
}

func decryptSharedPrivateKey(password []byte, encrypted Encrypted) (*ecdh.PrivateKey, bool) {
	salt, _ := base64.StdEncoding.DecodeString(encrypted.Salt)
	nonceBytes, _ := base64.StdEncoding.DecodeString(encrypted.Nonce)
	ciphertext, _ := base64.StdEncoding.DecodeString(encrypted.Data)
	key := secretKey(password, salt, encrypted.Params)
	defer wipeShared(key[:])
	var nonce [24]byte
	copy(nonce[:], nonceBytes)
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok || len(plaintext) != 32 {
		wipeShared(plaintext)
		return nil, false
	}
	defer wipeShared(plaintext)
	privateKey, err := ecdh.X25519().NewPrivateKey(plaintext)
	return privateKey, err == nil
}

// A sealed vault key contains the ephemeral X25519 public key, a nonce, and
// the NaCl secretbox ciphertext of the 32-byte vault key.
func wrapSharedKey(recipient *ecdh.PublicKey, vaultKey *[32]byte) (string, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	sharedSecret, err := ephemeral.ECDH(recipient)
	if err != nil {
		return "", err
	}
	defer wipeShared(sharedSecret)
	key := deriveSharedWrapKey(sharedSecret, ephemeral.PublicKey().Bytes(), recipient.Bytes())
	defer wipeShared(key[:])
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	wrapped := make([]byte, 0, 32+24+32+secretbox.Overhead)
	wrapped = append(wrapped, ephemeral.PublicKey().Bytes()...)
	wrapped = append(wrapped, nonce[:]...)
	wrapped = secretbox.Seal(wrapped, vaultKey[:], &nonce, &key)
	return base64.StdEncoding.EncodeToString(wrapped), nil
}

func unwrapSharedKey(private *ecdh.PrivateKey, encoded string) ([32]byte, error) {
	wrapped, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(wrapped) != 32+24+32+secretbox.Overhead {
		return [32]byte{}, errors.New("Invalid vault format: invalid wrapped vault key")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(wrapped[:32])
	if err != nil {
		return [32]byte{}, errors.New("Invalid vault format: invalid ephemeral public key")
	}
	sharedSecret, err := private.ECDH(ephemeral)
	if err != nil {
		return [32]byte{}, errors.New("Invalid vault format: invalid key exchange")
	}
	defer wipeShared(sharedSecret)
	key := deriveSharedWrapKey(sharedSecret, wrapped[:32], private.PublicKey().Bytes())
	defer wipeShared(key[:])
	var nonce [24]byte
	copy(nonce[:], wrapped[32:56])
	plaintext, ok := secretbox.Open(nil, wrapped[56:], &nonce, &key)
	if !ok || len(plaintext) != 32 {
		wipeShared(plaintext)
		return [32]byte{}, errors.New("Invalid vault format: cannot unwrap vault key")
	}
	var vaultKey [32]byte
	copy(vaultKey[:], plaintext)
	wipeShared(plaintext)
	return vaultKey, nil
}

// HKDF-SHA256 derives a domain-separated secretbox key from the X25519 result.
func deriveSharedWrapKey(sharedSecret, ephemeralPublic, recipientPublic []byte) [32]byte {
	mac := hmac.New(sha256.New, []byte("secrets-v2-X25519-keywrap"))
	mac.Write(sharedSecret)
	prk := mac.Sum(nil)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("secrets-v2-vault-key"))
	mac.Write(ephemeralPublic)
	mac.Write(recipientPublic)
	mac.Write([]byte{1})
	derived := mac.Sum(nil)
	var key [32]byte
	copy(key[:], derived)
	wipeShared(prk)
	wipeShared(derived)
	return key
}

func unlockShared(password []byte, shared Shared) ([32]byte, error) {
	if err := validateShared(shared); err != nil {
		return [32]byte{}, err
	}
	for _, user := range shared.Users {
		if isIdentityUser(user) {
			continue
		}
		privateKey, ok := decryptSharedPrivateKey(password, user.PrivateKey)
		if !ok {
			continue
		}
		publicKeyBytes, _ := base64.StdEncoding.DecodeString(user.PublicKey)
		if !hmac.Equal(privateKey.PublicKey().Bytes(), publicKeyBytes) {
			return [32]byte{}, errors.New("Invalid vault format: user public key does not match private key")
		}
		return unwrapSharedKey(privateKey, user.VaultKey)
	}
	return [32]byte{}, errors.New("Invalid vault password!")
}

func validateShared(shared Shared) error {
	if shared.Version != 2 || len(shared.Users) == 0 || len(shared.Users) > maxSharedUsers {
		return errors.New("Invalid vault format: unsupported version or user count")
	}
	nonce, err := base64.StdEncoding.DecodeString(shared.Nonce)
	if err != nil || len(nonce) != 24 {
		return errors.New("Invalid vault format: invalid nonce")
	}
	data, err := base64.StdEncoding.DecodeString(shared.Data)
	if err != nil || len(data) < secretbox.Overhead {
		return errors.New("Invalid vault format: invalid ciphertext")
	}
	names := make(map[string]bool)
	for _, user := range shared.Users {
		if strings.TrimSpace(user.Name) == "" || len(user.Name) > 64 || names[user.Name] {
			return errors.New("Invalid vault format: invalid user name")
		}
		names[user.Name] = true
		wrapped, err := base64.StdEncoding.DecodeString(user.VaultKey)
		if err != nil || len(wrapped) != 32+24+32+secretbox.Overhead {
			return errors.New("Invalid vault format: invalid wrapped vault key")
		}
		if isIdentityUser(user) {
			identifier, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(user.Name, "user-"))
			if err != nil || len(identifier) != 32 || user.PrivateKey.Data != "" || user.PrivateKey.Nonce != "" || user.PrivateKey.Salt != "" || len(user.PrivateKey.Params) != 0 {
				return errors.New("Invalid vault format: invalid identity user")
			}
			continue
		}
		public, err := base64.StdEncoding.DecodeString(user.PublicKey)
		if err != nil || len(public) != 32 {
			return errors.New("Invalid vault format: invalid public key")
		}
		if err := validateEncryptedPrivateKey(user.PrivateKey); err != nil {
			return fmt.Errorf("Invalid vault format: %w", err)
		}
	}
	return nil
}

func wipeShared(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

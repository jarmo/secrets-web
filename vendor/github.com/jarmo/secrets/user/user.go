package user

import (
	"crypto/ecdh"
	"errors"
	"regexp"

	"github.com/jarmo/secrets/crypto"
)

type User struct {
	Version  int
	Username string
	Identity crypto.Identity
}

var validUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func New(username string, password []byte) (User, error) {
	if !validUsername.MatchString(username) {
		return User{}, errors.New("Invalid user username")
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	identity, err := crypto.NewIdentity(password)
	if err != nil {
		return User{}, err
	}
	return User{Version: 1, Username: username, Identity: identity}, nil
}

func (user User) Validate() error {
	if user.Version != 1 || !validUsername.MatchString(user.Username) {
		return errors.New("Invalid user record")
	}
	return crypto.ValidateIdentity(user.Identity)
}

func (user User) Unlock(password []byte) (*ecdh.PrivateKey, error) {
	if err := user.Validate(); err != nil {
		return nil, err
	}
	return crypto.UnlockIdentity(password, user.Identity)
}

func (user User) ChangePassword(currentPassword, newPassword []byte) (User, error) {
	if err := ValidatePassword(newPassword); err != nil {
		return User{}, err
	}
	if err := user.Validate(); err != nil {
		return User{}, err
	}
	identity, err := crypto.ChangeIdentityPassword(currentPassword, newPassword, user.Identity)
	if err != nil {
		return User{}, err
	}
	user.Identity = identity
	return user, nil
}

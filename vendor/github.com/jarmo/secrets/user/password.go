package user

import "errors"

func ValidatePassword(password []byte) error {
	if len(password) < 12 || len(password) > 1024 {
		return errors.New("Password must be between 12 and 1024 bytes")
	}
	return nil
}

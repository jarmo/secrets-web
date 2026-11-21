package user

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxUserFileSize = 16 * 1024

func Register(directory, username string, password []byte) error {
	user, err := New(username, password)
	if err != nil {
		return err
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	data, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusiveFile(userPath(directory, username), data)
}

func Load(directory, username string) (User, error) {
	if !validUsername.MatchString(username) {
		return User{}, errors.New("Invalid user username")
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return User{}, err
	}
	path := userPath(directory, username)
	info, err := os.Lstat(path)
	if err != nil {
		return User{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxUserFileSize {
		return User{}, errors.New("Invalid user file")
	}
	file, err := os.Open(path)
	if err != nil {
		return User{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return User{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > maxUserFileSize {
		return User{}, errors.New("User file changed or is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxUserFileSize+1))
	if err != nil {
		return User{}, err
	}
	if len(data) > maxUserFileSize {
		return User{}, errors.New("Invalid user file")
	}
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return User{}, err
	}
	if user.Username != username {
		return User{}, errors.New("User username does not match its file")
	}
	return user, user.Validate()
}

func Authenticate(directory, username string, password []byte) (User, *ecdh.PrivateKey, error) {
	user, err := Load(directory, username)
	if err != nil {
		return User{}, nil, err
	}
	privateKey, err := user.Unlock(password)
	if err != nil {
		return User{}, nil, err
	}
	return user, privateKey, nil
}

func ChangePassword(directory, username string, currentPassword, newPassword []byte) error {
	user, err := Load(directory, username)
	if err != nil {
		return err
	}
	updated, err := user.ChangePassword(currentPassword, newPassword)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".user-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), userPath(directory, username))
}

func userPath(directory, username string) string {
	return filepath.Join(directory, username+".json")
}

func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	return checkPrivateDirectory(directory)
}

func checkPrivateDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("User directory must be private: %s", directory)
	}
	return nil
}

func writeExclusiveFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(file.Name())
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(file.Name())
		return err
	}
	return nil
}

func Destroy(directory, username string) error {
	if _, err := Load(directory, username); err != nil {
		return err
	}
	return os.Remove(userPath(directory, username))
}

package user

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const setupCodeLifetime = 48 * time.Hour

const maxPendingFileSize = 4 * 1024

type pendingUser struct {
	Version       int
	Username      string
	SetupCodeHash string
	ExpiresAt     time.Time
}

func CreatePending(directory, username string) (string, time.Time, error) {
	if !validUsername.MatchString(username) {
		return "", time.Time{}, errors.New("Invalid user username")
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return "", time.Time{}, err
	}
	if _, err := os.Lstat(userPath(directory, username)); err == nil {
		return "", time.Time{}, fmt.Errorf("User %s already exists: %w", username, os.ErrExist)
	} else if !os.IsNotExist(err) {
		return "", time.Time{}, err
	}

	pendingPath := pendingUserPath(directory, username)
	if existing, err := loadPending(directory, username); err == nil {
		if time.Now().Before(existing.ExpiresAt) {
			return "", time.Time{}, fmt.Errorf("User %s is awaiting activation: %w", username, os.ErrExist)
		}
		if err := os.Remove(pendingPath); err != nil {
			return "", time.Time{}, err
		}
	} else if !os.IsNotExist(err) {
		return "", time.Time{}, err
	}

	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().UTC().Add(setupCodeLifetime)
	codeHash := sha256.Sum256(codeBytes)
	pending := pendingUser{
		Version:       1,
		Username:      username,
		SetupCodeHash: base64.RawURLEncoding.EncodeToString(codeHash[:]),
		ExpiresAt:     expiresAt,
	}
	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return "", time.Time{}, err
	}
	if err := writeExclusiveFile(pendingPath, data); err != nil {
		return "", time.Time{}, err
	}
	return base64.RawURLEncoding.EncodeToString(codeBytes), expiresAt, nil
}

func Activate(directory, username, setupCode string, password []byte) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	pending, err := loadPending(directory, username)
	if err != nil {
		return err
	}
	if !time.Now().Before(pending.ExpiresAt) {
		return errors.New("User setup code has expired")
	}
	codeBytes, err := base64.RawURLEncoding.DecodeString(setupCode)
	if err != nil || len(codeBytes) != 32 {
		return errors.New("Invalid user setup code")
	}
	storedHash, err := base64.RawURLEncoding.DecodeString(pending.SetupCodeHash)
	if err != nil || len(storedHash) != sha256.Size {
		return errors.New("Invalid user setup record")
	}
	codeHash := sha256.Sum256(codeBytes)
	if subtle.ConstantTimeCompare(storedHash, codeHash[:]) != 1 {
		return errors.New("Invalid user setup code")
	}
	if err := Register(directory, username, password); err != nil {
		return err
	}
	return os.Remove(pendingUserPath(directory, username))
}

func loadPending(directory, username string) (pendingUser, error) {
	if !validUsername.MatchString(username) {
		return pendingUser{}, errors.New("Invalid user username")
	}
	if err := checkPrivateDirectory(directory); err != nil {
		return pendingUser{}, err
	}
	path := pendingUserPath(directory, username)
	info, err := os.Lstat(path)
	if err != nil {
		return pendingUser{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxPendingFileSize {
		return pendingUser{}, errors.New("Invalid user setup file")
	}
	file, err := os.Open(path)
	if err != nil {
		return pendingUser{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return pendingUser{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > maxPendingFileSize {
		return pendingUser{}, errors.New("User setup file changed or is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPendingFileSize+1))
	if err != nil {
		return pendingUser{}, err
	}
	if len(data) > maxPendingFileSize {
		return pendingUser{}, errors.New("Invalid user setup file")
	}
	var pending pendingUser
	if err := json.Unmarshal(data, &pending); err != nil {
		return pendingUser{}, err
	}
	if pending.Version != 1 || pending.Username != username || pending.ExpiresAt.IsZero() {
		return pendingUser{}, errors.New("Invalid user setup record")
	}
	if _, err := base64.RawURLEncoding.DecodeString(pending.SetupCodeHash); err != nil {
		return pendingUser{}, fmt.Errorf("Invalid user setup record: %w", err)
	}
	return pending, nil
}

func pendingUserPath(directory, username string) string {
	return filepath.Join(directory, username+".pending.json")
}

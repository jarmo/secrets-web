package storage

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"time"

	"github.com/jarmo/secrets/crypto"
	"github.com/jarmo/secrets/secret"
	"github.com/juju/fslock"
)

func Read(path string, password []byte) ([]secret.Secret, error) {
	if encryptedSecretsJSON, err := ioutil.ReadFile(path); os.IsNotExist(err) {
		return make([]secret.Secret, 0), nil
	} else {
		var encryptedSecrets crypto.Encrypted
		if err := json.Unmarshal(encryptedSecretsJSON, &encryptedSecrets); err != nil {
			panic(err)
		}

		if secrets, err := crypto.Decrypt(password, encryptedSecrets); err != nil {
			return secrets, err
		} else {
			return secrets, nil
		}
	}
}

func Write(path string, password []byte, decryptedSecrets []secret.Secret) {
	if fileLock, err := lock(path); err != nil {
		panic(err)
	} else {
		defer fileLock.Unlock()
	}

	encryptedSecrets := crypto.Encrypt(password, decryptedSecrets)

	if encryptedSecretsJSON, err := json.MarshalIndent(encryptedSecrets, "", "  "); err != nil {
		panic(err)
	} else if err := ioutil.WriteFile(path, encryptedSecretsJSON, 0600); err != nil {
		panic(err)
	}
}

func lock(path string) (*fslock.Lock, error) {
	lock := fslock.New(path)
	for i := 0; i < 5; i++ {
		err := lock.TryLock()
		if err == nil {
			return lock, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return nil, errors.New("Failed to lock " + path)
}

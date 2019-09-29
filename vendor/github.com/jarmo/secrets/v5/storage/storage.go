package storage

import(
  "os"
  "io/ioutil"
  "encoding/json"
  "github.com/jarmo/secrets/v5/crypto"
  "github.com/jarmo/secrets/v5/secret"
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
  encryptedSecrets := crypto.Encrypt(password, decryptedSecrets)

  if encryptedSecretsJSON, err := json.MarshalIndent(encryptedSecrets, "", "  "); err != nil {
    panic(err)
  } else if err := ioutil.WriteFile(path, encryptedSecretsJSON, 0600); err != nil {
    panic(err)
  }
}

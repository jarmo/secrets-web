package vault

import (
  "errors"
  "bytes"
  "github.com/jarmo/secrets/v5/secret"
  "github.com/jarmo/secrets/v5/storage"
  "github.com/jarmo/secrets/v5/vault/add"
  "github.com/jarmo/secrets/v5/vault/list"
  "github.com/jarmo/secrets/v5/vault/delete"
  "github.com/jarmo/secrets/v5/vault/edit"
  "github.com/satori/go.uuid"
)

func List(secrets []secret.Secret, filter string) []secret.Secret {
  return list.Execute(secrets, filter)
}

func Add(secrets []secret.Secret, name, value string) (secret.Secret, []secret.Secret) {
  newSecret, newSecrets := add.Execute(secrets, name, value)
  return newSecret, newSecrets
}

func Delete(secrets []secret.Secret, id uuid.UUID) (*secret.Secret, []secret.Secret, error) {
  existingSecretIndex := findIndexById(secrets, id)
  if existingSecretIndex == -1 {
    return nil, secrets, errors.New("Secret by specified id not found!")
  }

  deletedSecret, newSecrets := delete.Execute(secrets, existingSecretIndex)
  return &deletedSecret, newSecrets, nil
}

func Edit(secrets []secret.Secret, id uuid.UUID, newName, newValue string) (*secret.Secret, []secret.Secret, error) {
  existingSecretIndex := findIndexById(secrets, id)
  if existingSecretIndex == -1 {
    return nil, secrets, errors.New("Secret by specified id not found!")
  }

  editedSecret, newSecrets := edit.Execute(secrets, existingSecretIndex, newName, newValue)
  return &editedSecret, newSecrets, nil
}

func ChangePassword(storagePath string, currentPassword, newPassword, newPasswordConfirmation []byte) error {
  secrets, err := storage.Read(storagePath, currentPassword)
  if err != nil {
    return err
  }

  if !bytes.Equal(newPassword, newPasswordConfirmation) {
    return errors.New("Passwords do not match!")
  }
  storage.Write(storagePath, newPassword, secrets)

  return nil
}

func findIndexById(secrets []secret.Secret, id uuid.UUID) int {
  for index, secret := range secrets {
    if secret.Id == id {
      return index
    }
  }

  return -1
}

package edit

import (
  "github.com/jarmo/secrets/secret"
)

func Execute(secrets []secret.Secret, index int, newName, newValue string) (secret.Secret, []secret.Secret) {
  editedSecret := secrets[index]
  newSecret := secret.New(newName, newValue)
  newSecret.Id = editedSecret.Id
  secrets[index] = newSecret
  return newSecret, secrets
}


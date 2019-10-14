package add

import (
  "github.com/jarmo/secrets/secret"
)

func Execute(secrets []secret.Secret, name, value string) (secret.Secret, []secret.Secret) {
  newSecret := secret.New(name, value)
  return newSecret, append(secrets, newSecret)
}

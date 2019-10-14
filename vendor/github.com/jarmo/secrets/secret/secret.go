package secret

import (
  "fmt"
  "github.com/satori/go.uuid"
)

type Secret struct {
  Id uuid.UUID
  Name string
  Value string
}

func New(name, value string) Secret {
  return Secret{uuid.NewV4(), name, value}
}

func (secret Secret) String() string {
  return fmt.Sprintf(`
[%s]
%s
%s`, secret.Id, secret.Name, secret.Value)
}

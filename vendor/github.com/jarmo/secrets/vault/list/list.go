package list

import (
  "strings"
  "sort"
  "github.com/jarmo/secrets/secret"
)

func Execute(secrets []secret.Secret, filter string) []secret.Secret {
  var matches []secret.Secret
  for _, secret := range secrets {
    if secret.Id.String() == filter ||
         strings.Index(strings.ToLower(secret.Name), strings.ToLower(filter)) != -1 ||
         strings.Index(strings.ToLower(secret.Value), strings.ToLower(filter)) != -1 {
      matches = append(matches, secret)
    }
  }

  return sortByName(matches)
}

func sortByName(secrets []secret.Secret) []secret.Secret {
  sort.Slice(secrets, func(i, j int) bool { return strings.ToLower(secrets[i].Name) < strings.ToLower(secrets[j].Name) })
  return secrets
}

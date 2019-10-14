package path

import (
  "io/ioutil"
  "encoding/json"
  "errors"
  "github.com/jarmo/secrets/storage/path"
)

func Get(configurationPath, alias string) (string, error) {
  if configs, err := path.Configurations(configurationPath); err == nil {
    if confByAlias := path.FindByAlias(configs, alias); confByAlias != nil {
      return confByAlias.Path, nil
    } else {
      return "", errors.New("Vault not found!")
    }
  } else {
    return "", err
  }
}

func Store(configurationPath, vaultPath, vaultAlias string) string {
  conf, _ := path.Configurations(configurationPath)
  conf = append(conf, path.Config{Path: vaultPath, Alias: vaultAlias})

  if configJSON, err := json.MarshalIndent(conf, "", " "); err != nil {
    panic(err)
  } else if err := ioutil.WriteFile(configurationPath, configJSON, 0600); err != nil {
    panic(err)
  }

  return configurationPath
}


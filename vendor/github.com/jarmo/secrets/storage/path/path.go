package path

import (
  "os"
  "io/ioutil"
  "encoding/json"
  "errors"
  "github.com/pinzolo/xdgdir"
)

type Config struct {
  Path string
  Alias string
}

func Get(alias string) (string, error) {
  if configs, err := Configurations(configurationPath()); err == nil {
    if confByAlias := FindByAlias(configs, alias); confByAlias != nil {
      return confByAlias.Path, nil
    } else {
      return configs[0].Path, nil
    }
  } else {
    return "", err
  }
}

func Store(vaultPath string, vaultAlias string) string {
  configurationPath := configurationPath()
  conf, _ := Configurations(configurationPath)
  conf = append(conf, Config{Path: vaultPath, Alias: vaultAlias})

  if configJSON, err := json.MarshalIndent(conf, "", " "); err != nil {
    panic(err)
  } else if err := ioutil.WriteFile(configurationPath, configJSON, 0600); err != nil {
    panic(err)
  }

  return configurationPath
}

func Configurations(path string) ([]Config, error) {
  if configJSON, err := ioutil.ReadFile(path); os.IsNotExist(err) {
    return make([]Config, 0), errors.New("Vault is not configured!")
  } else {
    var conf []Config
    if err := json.Unmarshal(configJSON, &conf); err == nil {
      return conf, nil
    } else {
      return make([]Config, 0), err
    }
  }
}

func FindByAlias(configs []Config, alias string) *Config {
  for _, config := range configs {
    if config.Alias == alias {
      return &config
    }
  }

  return nil
}

func configurationPath() string {
  xdgApp := xdgdir.NewApp("secrets")
  xdgConfigurationFilePath, err := xdgApp.ConfigFile("config.json")
  if err != nil {
    panic(err)
  }

  return xdgConfigurationFilePath
}

package command

import (
  "errors"
  "strings"
  "os"
  "io/ioutil"
  "path/filepath"
  "strconv"

  "github.com/jarmo/secrets-web/router"
  "github.com/jarmo/secrets/user"
)

type Serve struct {
  ConfigurationPath string
  CertificatePath string
  CertificatePrivKeyPath string
  Host string
  Port string
  Pid string
  UsersDirectory string
}

func (command Serve) Execute() {
  if err := serveUntilExit(command); err != nil {
    panic(err)
  }
}

func serveUntilExit(command Serve) error {
  isProdMode := isProdMode()
  configurationPath, usersDirectory, err := resolveStoragePaths(command.ConfigurationPath, command.UsersDirectory)
  if err != nil {
    return err
  }
  router := router.Create(configurationPath, usersDirectory, isProdMode)
  port := argumentOrDefault(command.Port, "9090")

  if command.Pid != "" {
    writePidToFile(command.Pid)
  }

  if isProdMode {
    host := argumentOrDefault(command.Host, "0.0.0.0")
    return router.RunTLS(host + ":" + port, command.CertificatePath, command.CertificatePrivKeyPath)
  } else {
    return router.Run("localhost:" + port)
  }

}

func resolveStoragePaths(configurationPath, usersDirectory string) (string, string, error) {
  if configurationPath != "" && usersDirectory != "" {
    return configurationPath, usersDirectory, nil
  }

  configHome := os.Getenv("XDG_CONFIG_HOME")
  if configHome == "" {
    home := os.Getenv("HOME")
    if home == "" {
      home = os.Getenv("USERPROFILE")
    }
    if home == "" {
      return "", "", errors.New("cannot determine secrets configuration directory")
    }
    configHome = filepath.Join(home, ".config")
  }

  secretsDirectory := filepath.Join(configHome, "secrets")
  if configurationPath == "" {
    configurationPath = filepath.Join(secretsDirectory, "config.json")
  }
  if usersDirectory == "" {
    usersDirectory = user.DefaultDirectory(secretsDirectory)
  }
  return configurationPath, usersDirectory, nil
}

func writePidToFile(path string) {
  if err := ioutil.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
    panic(err)
  }
}

func argumentOrDefault(argument, defaultArgument string) string {
  if argument != "" {
    return argument
  } else {
    return defaultArgument
  }
}

func isProdMode() bool {
  binary, err := os.Executable()
  if err != nil {
    panic(err)
  }
  binaryDir := filepath.Dir(binary)

  return !strings.HasPrefix(binaryDir, os.TempDir())
}


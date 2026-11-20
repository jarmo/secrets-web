package command

import (
  "errors"
  "strings"
  "os"
  "io/ioutil"
  "path/filepath"
  "strconv"

  "github.com/jarmo/secrets-web/router"
)

type Serve struct {
  ConfigurationPath string
  CertificatePath string
  CertificatePrivKeyPath string
  Host string
  Port string
  Pid string
  MembersDirectory string
}

func (command Serve) Execute() {
  if err := serveUntilExit(command); err != nil {
    panic(err)
  }
}

func serveUntilExit(command Serve) error {
  isProdMode := isProdMode()
  configurationPath, membersDirectory, err := resolveStoragePaths(command.ConfigurationPath, command.MembersDirectory)
  if err != nil {
    return err
  }
  router := router.Create(configurationPath, membersDirectory, isProdMode)
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

func resolveStoragePaths(configurationPath, membersDirectory string) (string, string, error) {
  if configurationPath != "" && membersDirectory != "" {
    return configurationPath, membersDirectory, nil
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
  if membersDirectory == "" {
    membersDirectory = filepath.Join(secretsDirectory, "members")
  }
  return configurationPath, membersDirectory, nil
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


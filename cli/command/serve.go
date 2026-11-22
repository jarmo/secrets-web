package command

import (
  "errors"
  "os"
  "io/ioutil"
  "path/filepath"
  "strconv"

  "github.com/jarmo/secrets-web/router"
  "github.com/jarmo/secrets/user"
  "github.com/jarmo/secrets/storage/path"
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
  isProdMode, err := useTLS(command.CertificatePath, command.CertificatePrivKeyPath)
  if err != nil {
    return err
  }
  if !isProdMode && command.Host != "" && command.Host != "localhost" && command.Host != "127.0.0.1" && command.Host != "::1" {
    return errors.New("HTTP development mode is restricted to localhost")
  }
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
    configured, err := path.UsersDirectory(configurationPath)
    if err != nil {
      return "", "", err
    }
    if configured != "" {
      usersDirectory = configured
    } else {
      usersDirectory = user.DefaultDirectory(secretsDirectory)
    }
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

// Only the explicit development sentinel disables TLS. The binary's path
// (including a temporary build/run directory) must never determine whether
// passwords are sent over HTTP or whether session cookies are Secure.
func useTLS(certPath, keyPath string) (bool, error) {
  if certPath == "none" && keyPath == "none" {
    return false, nil
  }
  if certPath == "" || keyPath == "" || certPath == "none" || keyPath == "none" {
    return false, errors.New("An HTTPS certificate and private key are required (use none/none only for local development)")
  }
  return true, nil
}


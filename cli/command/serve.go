package command

import (
  "strings"
  "os"
  "path/filepath"

  "github.com/jarmo/secrets-web/router"
)

type Serve struct {
  ConfigurationPath string
  CertificatePath string
  CertificatePrivKeyPath string
  Host string
  Port string
}

func (command Serve) Execute() {
  isProdMode := isProdMode()
  router := router.Create(command.ConfigurationPath, isProdMode)
  port := argumentOrDefault(command.Port, "9090")

  if isProdMode {
    host := argumentOrDefault(command.Host, "0.0.0.0")
    router.RunTLS(host + ":" + port, command.CertificatePath, command.CertificatePrivKeyPath)
  } else {
    router.Run("localhost:" + port)
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


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
  port := port(command.Port)

  if isProdMode {
    router.RunTLS(":" + port, command.CertificatePath, command.CertificatePrivKeyPath)
  } else {
    router.Run("localhost:" + port)
  }
}

func port(portFromCommandLine string) string {
  if portFromCommandLine != "" {
    return portFromCommandLine
  } else {
    return "9090"
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


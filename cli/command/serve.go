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
}

func (command Serve) Execute() {
  isProdMode := isProdMode()
  router := router.Create(command.ConfigurationPath, isProdMode)

  if isProdMode {
    router.RunTLS(":9090", command.CertificatePath, command.CertificatePrivKeyPath)
  } else {
    router.Run("localhost:8080")
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


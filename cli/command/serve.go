package command

import (
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
}

func (command Serve) Execute() {
  if err := serveUntilExit(command); err != nil {
    panic(err)
  }
}

func serveUntilExit(command Serve) error {
  isProdMode := isProdMode()
  router := router.Create(command.ConfigurationPath, isProdMode)
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


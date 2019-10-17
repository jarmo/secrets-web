package command

import (
  "strings"
  "os"
  "path/filepath"

  "github.com/gin-contrib/secure"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/handlers"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/generated"
  "github.com/jarmo/secrets-web/templates"
)

type Serve struct {
  ConfigurationPath string
  CertificatePath string
  CertificatePrivKeyPath string
}

func (command Serve) Execute() {
  isProdMode := isProdMode()
  app := initialize(command.ConfigurationPath, isProdMode)

  if isProdMode {
    app.RunTLS(":9090", command.CertificatePath, command.CertificatePrivKeyPath)
  } else {
    app.Run("localhost:8080")
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

func initialize(configurationPath string, prodModeEnabled bool) *gin.Engine {
  if prodModeEnabled {
    gin.SetMode(gin.ReleaseMode)
  }

  router := gin.Default()

  if prodModeEnabled {
    router.Use(secure.New(secure.DefaultConfig()))
  }

  router.Use(session.CreateCookie(prodModeEnabled))

  if templates, err := templates.Create(); err != nil {
    panic(err)
  } else {
    router.SetHTMLTemplate(templates)
  }

  router.StaticFS("/public", generated.Assets)
  router.Use(middleware.CsrfProtection())

  router.POST("/login", handlers.Login(configurationPath))

  authenticated := router.Group("", middleware.Authenticated(configurationPath))
  authenticated.GET("/", handlers.Index)
  authenticated.POST("/", handlers.Filter)
  authenticated.POST("/add", handlers.Add)
  authenticated.POST("/edit/:id", handlers.Edit)
  authenticated.POST("/delete/:id", handlers.Delete)

  return router
}

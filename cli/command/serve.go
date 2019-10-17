package command

import (
  "net/http"
  "html/template"
  "io/ioutil"
  "strings"
  "os"
  "path/filepath"

  "github.com/satori/go.uuid"
  "github.com/gin-contrib/sessions"
  "github.com/gin-contrib/sessions/cookie"
  "github.com/gin-contrib/secure"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/vault"
  "github.com/jarmo/secrets/crypto"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/generated"
  "github.com/jarmo/secrets-web/redirect"
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

func templates() (*template.Template, error) {
  tmpl := template.New("")
  for name, file := range generated.Assets.Files {
    if file.IsDir() || !strings.HasSuffix(name, ".tmpl") {
      continue
    }
    content, err := ioutil.ReadAll(file)
    if err != nil {
      return nil, err
    }
    tmpl, err = tmpl.New(name).Parse(string(content))
    if err != nil {
      return nil, err
    }
  }
  return tmpl, nil
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

  sessionStore := cookie.NewStore(crypto.GenerateRandomBytes(64), crypto.GenerateRandomBytes(32))
  sessionStore.Options(sessions.Options{
    Path: "/",
    MaxAge: session.MaxAgeInSeconds,
    HttpOnly: true,
    Secure: prodModeEnabled,
  })

  router.Use(sessions.Sessions("secrets", sessionStore))

  if tmpls, err := templates(); err != nil {
    panic(err)
  } else {
    router.SetHTMLTemplate(tmpls)
  }

  router.StaticFS("/public", generated.Assets)
  router.Use(middleware.CsrfProtection())

  router.POST("/login", func(c *gin.Context) {
    if vault, err := session.Create(configurationPath, c); err != nil {
      c.HTML(http.StatusOK, "/templates/login.tmpl", gin.H{
	"error": err,
	"user": vault.Alias,
      })
    } else {
      redirect.WithMessage(c, "/", "Logged in successfully")
    }
  })

  protected := router.Group("", middleware.Authenticated(configurationPath))

  protected.GET("/", func(c *gin.Context) {
    c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
      "message": redirect.Message(c),
    })
  })

  protected.POST("/", func(c *gin.Context) {
    filter := c.PostForm("filter")
    vaultSession := c.MustGet("session").(session.Vault)
    result := vault.List(vaultSession.Secrets, filter)

    c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
      "filter":  filter,
      "secrets": result,
    })
  })

  protected.POST("/add", func(c *gin.Context) {
    name := c.PostForm("name")
    value := c.PostForm("value")
    sessionVault := c.MustGet("session").(session.Vault)

    _, newSecrets := vault.Add(sessionVault.Secrets, name, value)
    storage.Write(sessionVault.Path, sessionVault.Password, newSecrets)
    redirect.WithMessage(c, "/", "Added successfully")
  })

  protected.POST("/edit/:id", func(c *gin.Context) {
    id, _ := uuid.FromString(c.Param("id"))
    name := c.PostForm("name")
    value := c.PostForm("value")
    sessionVault := c.MustGet("session").(session.Vault)

    if _, newSecrets, err := vault.Edit(sessionVault.Secrets, id, name, value); err != nil {
      c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
	"error": err,
      })
    } else {
      storage.Write(sessionVault.Path, sessionVault.Password, newSecrets)
      redirect.WithMessage(c, "/", "Edited successfully")
    }
  })

  protected.POST("/delete/:id", func(c *gin.Context) {
    id, _ := uuid.FromString(c.Param("id"))
    sessionVault := c.MustGet("session").(session.Vault)

    if _, newSecrets, err := vault.Delete(sessionVault.Secrets, id); err != nil {
      c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
	"error": err,
      })
    } else {
      storage.Write(sessionVault.Path, sessionVault.Password, newSecrets)
      redirect.WithMessage(c, "/", "Deleted successfully")
    }
  })

  return router
}

package command

import (
	"net/http"
	"html/template"
	"io/ioutil"
	"encoding/base64"
	"strings"
	"errors"
	"os"
	"path/filepath"

	"github.com/satori/go.uuid"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/jarmo/secrets/secret"
	"github.com/jarmo/secrets/storage"
	"github.com/jarmo/secrets/storage/path"
	"github.com/jarmo/secrets/vault"
	"github.com/jarmo/secrets/crypto"
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

type session struct {
	vaultAlias string
	path string
	password []byte
	secrets []secret.Secret
}

const sessionMaxAgeInSeconds = 5 * 60

func authenticated(configurationPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if session, err := createSession(configurationPath, c); err != nil {
			c.HTML(http.StatusForbidden, "/templates/login.tmpl", gin.H{
			  "sessionMaxAgeInSeconds": sessionMaxAgeInSeconds,
			  "csrfToken": csrfToken(sessions.Default(c)),
			})
			c.AbortWithStatus(http.StatusForbidden)
		} else {
			c.Set("session", session)
		}
	}
}

func csrfToken(session sessions.Session) string {
	csrfToken := session.Get("csrfToken")
	if csrfToken == nil {
		newCsrfToken := base64.StdEncoding.EncodeToString(crypto.GenerateRandomBytes(128))
		session.Set("csrfToken", newCsrfToken)
		session.Save()
		return newCsrfToken
	} else {
		return csrfToken.(string)
	}
}

func csrfProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		request := c.Request
		if request.Method != "HEAD" && request.Method != "GET" {
			if csrfToken(sessions.Default(c)) != c.GetHeader("X-Csrf-Token") {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
		c.Next()
	}
}

func createSession(configurationPath string, c *gin.Context) (session, error) {
	if decodedCredentialsHeader, err := base64.StdEncoding.DecodeString(c.GetHeader("X-Credentials")); err != nil {
		return session{}, errors.New("Invalid X-Credentials header")
	} else if len(decodedCredentialsHeader) == 0 {
		return session{}, errors.New("No X-Credentials header value")
	} else {
		credentials := strings.Split(string(decodedCredentialsHeader), ":")
		vaultAlias := credentials[0]

		if len(credentials) != 2 {
			return session{vaultAlias: vaultAlias}, errors.New("Invalid X-Credentials header value")
		} else {
			password := credentials[1]
			if path, aliasErr := path.Get(configurationPath, vaultAlias); aliasErr != nil {
				return session{vaultAlias: vaultAlias}, aliasErr
			} else {
				if secrets, vaultErr := storage.Read(path, []byte(password)); vaultErr != nil {
					return session{vaultAlias: vaultAlias}, vaultErr
				} else {
					return session{vaultAlias: vaultAlias, path: path, password: []byte(password), secrets: secrets}, nil
				}
			}
		}
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
		MaxAge: sessionMaxAgeInSeconds,
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
	router.Use(csrfProtection())

	router.POST("/login", func(c *gin.Context) {
		if session, err := createSession(configurationPath, c); err != nil {
			c.HTML(http.StatusOK, "/templates/login.tmpl", gin.H{
				"error": err,
				"user": session.vaultAlias,
			})
		} else {
			redirect.WithMessage(c, "/", "Logged in successfully")
		}
	})

	protected := router.Group("", authenticated(configurationPath))

	protected.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
			"message": redirect.Message(c),
		})
	})

	protected.POST("/", func(c *gin.Context) {
		filter := c.PostForm("filter")
		session := c.MustGet("session").(session)
		result := vault.List(session.secrets, filter)

		c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
			"filter":  filter,
			"secrets": result,
		})
	})

	protected.POST("/add", func(c *gin.Context) {
		name := c.PostForm("name")
		value := c.PostForm("value")
		session := c.MustGet("session").(session)

		_, newSecrets := vault.Add(session.secrets, name, value)
		storage.Write(session.path, session.password, newSecrets)
		redirect.WithMessage(c, "/", "Added successfully")
	})

	protected.POST("/edit/:id", func(c *gin.Context) {
		id, _ := uuid.FromString(c.Param("id"))
		name := c.PostForm("name")
		value := c.PostForm("value")
		session := c.MustGet("session").(session)

		if _, newSecrets, err := vault.Edit(session.secrets, id, name, value); err != nil {
			c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
				"error": err,
			})
		} else {
			storage.Write(session.path, session.password, newSecrets)
			redirect.WithMessage(c, "/", "Edited successfully")
		}
	})

	protected.POST("/delete/:id", func(c *gin.Context) {
		id, _ := uuid.FromString(c.Param("id"))
		session := c.MustGet("session").(session)

		if _, newSecrets, err := vault.Delete(session.secrets, id); err != nil {
			c.HTML(http.StatusOK, "/templates/index.tmpl", gin.H{
				"error": err,
			})
		} else {
			storage.Write(session.path, session.password, newSecrets)
			redirect.WithMessage(c, "/", "Deleted successfully")
		}
	})

	return router
}

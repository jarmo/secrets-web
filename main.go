package main

import (
	"net/http"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"errors"

	"github.com/satori/go.uuid"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jarmo/secrets/v5/secret"
	"github.com/jarmo/secrets/v5/storage"
	"github.com/jarmo/secrets/v5/storage/path"
	"github.com/jarmo/secrets/v5/vault"
)

type session struct {
	vaultAlias string
	path string
	password []byte
	secrets []secret.Secret
}

func redirect(c *gin.Context, path string) {
	c.Redirect(http.StatusFound, path)
	c.AbortWithStatus(http.StatusFound)
}

func redirectWithMessage(c *gin.Context, path string, message string) {
	session := sessions.Default(c)
	session.AddFlash(message)
	session.Save()
	redirect(c, path)
}

func redirectMessage(c *gin.Context) interface{} {
		session := sessions.Default(c)
		if flashes := session.Flashes(); len(flashes) > 0 {
		  message := flashes[0].(string)
			session.Save()
			return message
		} else {
			return nil
		}
}

func authenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		if session, err := createSession(c); err != nil {
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"sessionMaxAgeInSeconds": sessionMaxAgeInSeconds,
				"csrfToken": csrfToken(sessions.Default(c)),
			})
			c.AbortWithStatus(http.StatusOK)
		} else {
			c.Set("session", session)
		}
	}
}

func generateRandomBytes(length int) []byte {
  result := make([]byte, length)
  _, err := rand.Read(result)
  if err != nil {
    panic(err)
  }

  return result
}

func csrfToken(session sessions.Session) string {
	csrfToken := session.Get("csrfToken")
	if csrfToken == nil {
		newCsrfToken := base64.StdEncoding.EncodeToString(generateRandomBytes(128))
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

func createSession(c *gin.Context) (session, error) {
	if decodedAuthorizationHeader, err := base64.StdEncoding.DecodeString(strings.Replace(c.GetHeader("Authorization"), "Bearer ", "", 1)); err != nil {
		return session{}, errors.New("Invalid Authorization header")
	} else if len(decodedAuthorizationHeader) == 0 {
		return session{}, errors.New("Not logged in")
	} else {
		credentials := strings.Split(string(decodedAuthorizationHeader), ":")
		vaultAlias := credentials[0]

		if len(credentials) != 2 {
			return session{vaultAlias: vaultAlias}, errors.New("Invalid Authorization header value")
		} else {
			password := credentials[1]
			if path, aliasErr := path.Get(vaultAlias); aliasErr != nil {
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

const sessionMaxAgeInSeconds = 5 * 60

func setupRouter() *gin.Engine {
	router := gin.Default()
	sessionStore := cookie.NewStore(generateRandomBytes(64), generateRandomBytes(32))
	sessionStore.Options(sessions.Options{
		Path: "/",
		MaxAge: sessionMaxAgeInSeconds,
		HttpOnly: true,
	})

	router.Use(sessions.Sessions("secrets", sessionStore))
	router.LoadHTMLGlob("templates/*")
	router.Static("/assets", "./assets")
	router.Use(csrfProtection())

	router.POST("/login", func(c *gin.Context) {
		if session, err := createSession(c); err != nil {
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"error": err,
				"user": session.vaultAlias,
			})
		} else {
			redirectWithMessage(c, "/", "Logged in successfully")
		}
	})

	protected := router.Group("", authenticated())

	protected.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"message": redirectMessage(c),
		})
	})

	protected.POST("/", func(c *gin.Context) {
		filter := c.PostForm("filter")
		session := c.MustGet("session").(session)
		result := vault.List(session.secrets, filter)

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
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
		redirectWithMessage(c, "/", "Added successfully")
	})

	protected.POST("/edit/:id", func(c *gin.Context) {
		id, _ := uuid.FromString(c.Param("id"))
		name := c.PostForm("name")
		value := c.PostForm("value")
		session := c.MustGet("session").(session)

		if _, newSecrets, err := vault.Edit(session.secrets, id, name, value); err != nil {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"error": err,
			})
		} else {
			storage.Write(session.path, session.password, newSecrets)
			redirectWithMessage(c, "/", "Edited successfully")
		}
	})

	protected.POST("/delete/:id", func(c *gin.Context) {
		id, _ := uuid.FromString(c.Param("id"))
		session := c.MustGet("session").(session)

		if _, newSecrets, err := vault.Delete(session.secrets, id); err != nil {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"error": err,
			})
		} else {
			storage.Write(session.path, session.password, newSecrets)
			redirectWithMessage(c, "/", "Deleted successfully")
		}
	})

	return router
}

func main() {
	r := setupRouter()
	r.Run("localhost:8080")
}

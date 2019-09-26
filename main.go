package main

import (
	"net/http"
	"crypto/rand"

	"github.com/satori/go.uuid"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/jarmo/secrets/v5/storage"
	"github.com/jarmo/secrets/v5/storage/path"
	"github.com/jarmo/secrets/v5/vault"
)

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
		session := sessions.Default(c)

		if session.Get("vaultPath") == nil {
			redirect(c, "/login")
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

func setupRouter() *gin.Engine {
	router := gin.Default()
	sessionStore := cookie.NewStore(generateRandomBytes(64), generateRandomBytes(32))

	router.Use(sessions.Sessions("secrets", sessionStore))
	router.LoadHTMLGlob("templates/*")
	router.Static("/assets", "./assets")

	router.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("vaultPath") != nil {
			redirect(c, "/")
		} else {
			c.HTML(http.StatusOK, "login.tmpl", gin.H{})
		}
	})

	router.POST("/login", func(c *gin.Context) {
		vaultAlias := c.PostForm("vault-alias")
		password := c.PostForm("password")

		if path, aliasErr := path.Get(vaultAlias); aliasErr != nil {
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"error": aliasErr,
				"user":  vaultAlias,
			})
		} else {
			if _, vaultErr := storage.Read(path, []byte(password)); vaultErr != nil {
				c.HTML(http.StatusOK, "login.tmpl", gin.H{
					"error": vaultErr,
					"user":  vaultAlias,
				})
			} else {
				session := sessions.Default(c)
				session.Set("vaultPath", path)
				session.Set("password", password)
				session.Save()
				redirectWithMessage(c, "/", "Logged in successfully")
			}
		}
	})

	protected := router.Group("", authenticated())

	protected.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"message": redirectMessage(c),
		})
	})

	protected.POST("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		redirect(c, "/login")
	})

	protected.POST("/", func(c *gin.Context) {
		filter := c.PostForm("filter")
		session := sessions.Default(c)
		secrets, readErr := storage.Read(session.Get("vaultPath").(string), []byte(session.Get("password").(string)))
		result := vault.List(secrets, filter)

		c.HTML(http.StatusOK, "index.tmpl", gin.H{
			"error":   readErr,
			"filter":  filter,
			"secrets": result,
		})
	})

	protected.POST("/add", func(c *gin.Context) {
		name := c.PostForm("name")
		value := c.PostForm("value")
		session := sessions.Default(c)
		path := session.Get("vaultPath").(string)
		password := []byte(session.Get("password").(string))

		if secrets, readErr := storage.Read(path, password); readErr != nil {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"error": readErr,
			})
		} else {
		  _, newSecrets := vault.Add(secrets, name, value)
			storage.Write(path, password, newSecrets)
			redirectWithMessage(c, "/", "Added successfully")
		}
	})

	protected.POST("/edit/:id", func(c *gin.Context) {
		id, _ := uuid.FromString(c.Param("id"))
		name := c.PostForm("name")
		value := c.PostForm("value")
		session := sessions.Default(c)
		path := session.Get("vaultPath").(string)
		password := []byte(session.Get("password").(string))

		if secrets, readErr := storage.Read(path, password); readErr != nil {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"error": readErr,
			})
		} else {
			if _, newSecrets, err := vault.Edit(secrets, id, name, value); err != nil {
				c.HTML(http.StatusOK, "index.tmpl", gin.H{
					"error": err,
				})
			} else {
				storage.Write(path, password, newSecrets)
				redirectWithMessage(c, "/", "Edited successfully")
			}
		}
	})

	protected.POST("/delete/:id", func(c *gin.Context) {
		id, _ := uuid.FromString(c.Param("id"))
		session := sessions.Default(c)
		path := session.Get("vaultPath").(string)
		password := []byte(session.Get("password").(string))

		if secrets, readErr := storage.Read(path, password); readErr != nil {
			c.HTML(http.StatusOK, "index.tmpl", gin.H{
				"error": readErr,
			})
		} else {
			if _, newSecrets, err := vault.Delete(secrets, id); err != nil {
				c.HTML(http.StatusOK, "index.tmpl", gin.H{
					"error": err,
				})
			} else {
				storage.Write(path, password, newSecrets)
				redirectWithMessage(c, "/", "Deleted successfully")
			}
		}
	})

	return router
}

func main() {
	r := setupRouter()
	r.Run("localhost:8080")
}

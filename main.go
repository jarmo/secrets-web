package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/jarmo/secrets/v5/storage"
	"github.com/jarmo/secrets/v5/storage/path"
	"github.com/jarmo/secrets/v5/vault"
)

func redirect(c *gin.Context, path string) {
	c.Redirect(http.StatusFound, path)
	c.AbortWithStatus(http.StatusFound)
}

func authenticated() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if session.Get("vaultPath") == nil {
			redirect(c, "/login")
		}
	}
}

func setupRouter() *gin.Engine {
	router := gin.Default()
	sessionSecret := os.Getenv("SECRETS_SESSION_SECRET")
	if sessionSecret == "" {
		fmt.Fprintln(os.Stderr, "SECRETS_SESSION_SECRET environment variable not set!")
		os.Exit(1)
	}
	memstore := memstore.NewStore([]byte(sessionSecret))

	router.Use(sessions.Sessions("secrets", memstore))
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
				redirect(c, "/")
			}
		}
	})

	protected := router.Group("", authenticated())

	protected.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl", gin.H{})
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

	return router
}

func main() {
	r := setupRouter()
	r.Run("localhost:8080")
}

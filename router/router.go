package router

import (
  "html/template"

  "github.com/gin-contrib/secure"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/handlers"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/generated"
  "github.com/jarmo/secrets-web/templates"
)

func Create(configurationPath, usersDirectory string, prodModeEnabled bool) *gin.Engine {
  if prodModeEnabled {
    gin.SetMode(gin.ReleaseMode)
  }

  router := gin.Default()

  if prodModeEnabled {
    router.Use(secure.New(secure.DefaultConfig()))
  }

  router.SetHTMLTemplate(initTemplates())
  router.Use(session.CreateCookie(prodModeEnabled))
  router.Use(middleware.CacheControl())
  router.Use(middleware.CsrfProtection())
  router.StaticFS("/public", generated.Assets)
  initRoutes(router, configurationPath, usersDirectory, session.NewUserSessions())

  return router
}

func initRoutes(router *gin.Engine, configurationPath, usersDirectory string, users *session.UserSessions) {
  router.POST("/logout", handlers.Logout(users))
  userRoutes := router.Group("", func(c *gin.Context) {
    userSession, ok := users.Current(c)
    if !ok {
      c.Redirect(303, "/")
      c.Abort()
      return
    }
    c.Set("userSession", userSession)
  })
  userRoutes.GET("/settings", handlers.Settings)
  userRoutes.POST("/settings/password", handlers.ChangeUserPassword(usersDirectory, users))
  userRoutes.GET("/vaults", handlers.Vaults(configurationPath))
  userVault := userRoutes.Group("/vaults/:alias", middleware.VaultAccess(configurationPath))
  userVault.GET("", handlers.Index)
  userVault.GET("/secrets", handlers.List)
  userVault.POST("", handlers.Create)
  userVault.PUT("/:id", handlers.Edit)
  userVault.DELETE("/:id", handlers.Delete)

  router.POST("/login", handlers.Login(configurationPath, usersDirectory, users))
  router.GET("/activate", handlers.ActivationForm)
  router.POST("/activate", handlers.Activate(usersDirectory))

  router.GET("/", func(c *gin.Context) {
    if _, ok := users.Current(c); ok {
      c.Redirect(303, "/vaults")
      return
    }
    middleware.Authenticated(configurationPath)(c)
    if c.IsAborted() {
      return
    }
    handlers.Index(c)
  })

  authenticated := router.Group("", middleware.Authenticated(configurationPath))
  authenticated.GET("/secrets", handlers.List)
  authenticated.POST("/secrets", handlers.Create)
  authenticated.PUT("/secrets/:id", handlers.Edit)
  authenticated.DELETE("/secrets/:id", handlers.Delete)
}

func initTemplates() *template.Template {
  if templates, err := templates.Create(); err != nil {
    panic(err)
  } else {
    return templates
  }
}

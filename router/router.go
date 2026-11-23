package router

import (
  "html/template"
  "net/http"

  "github.com/gin-contrib/sessions"

  "github.com/gin-contrib/secure"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets-web/middleware"
  "github.com/jarmo/secrets-web/handlers"
  "github.com/jarmo/secrets-web/session"
  "github.com/jarmo/secrets-web/generated"
  "github.com/jarmo/secrets-web/templates"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/storage/path"
)

func Create(configurationPath, usersDirectory string, prodModeEnabled bool) *gin.Engine {
  if prodModeEnabled {
    gin.SetMode(gin.ReleaseMode)
  }

  router := gin.Default()

  if prodModeEnabled {
    policy := secure.DefaultConfig()
    policy.ReferrerPolicy = "no-referrer"
    policy.FeaturePolicy = "camera 'none'; microphone 'none'; geolocation 'none'"
    router.Use(secure.New(policy))
  }

  router.SetHTMLTemplate(initTemplates())
  router.Use(session.CreateCookie(prodModeEnabled))
  router.Use(middleware.CacheControl())
  router.Use(middleware.RequestSize())
  router.Use(middleware.CsrfProtection())
  router.StaticFS("/public", generated.Assets)
  initRoutes(router, configurationPath, usersDirectory, session.NewUserSessions(usersDirectory))

  return router
}

func initRoutes(router *gin.Engine, configurationPath, usersDirectory string, users *session.UserSessions) {
  authLimit := middleware.NewAuthLimiter()
  legacyLimit := middleware.NewLegacyAuthLimiter()
  router.POST("/logout", handlers.Logout(users))
  router.GET("/session/status", func(c *gin.Context) {
    userSession, ok := users.Inspect(c)
    if !ok {
      c.Status(401)
      return
    }
    if alias := c.Query("vault"); alias != "" {
      vaultPath, err := path.Get(configurationPath, alias)
      if err != nil {
        c.Status(403)
        return
      }
      if err := storage.CanAccessForUser(vaultPath, userSession.PrivateKey); err != nil {
        c.Status(403)
        return
      }
    }
    c.Status(204)
  })
  userRoutes := router.Group("", func(c *gin.Context) {
    userSession, ok := users.Current(c)
    if !ok {
      c.Redirect(303, "/")
      c.Abort()
      return
    }
    c.Set("userSession", userSession)
  })
  userRoutes.GET("/settings", handlers.VaultNavigation(configurationPath), handlers.Settings)
  userRoutes.POST("/settings/password", handlers.ChangeUserPassword(usersDirectory, users))
  userRoutes.GET("/vaults", handlers.VaultNavigation(configurationPath), handlers.Vaults(configurationPath))
  userVault := userRoutes.Group("/vaults/:alias", middleware.VaultAccess(configurationPath))
  userVault.GET("", handlers.VaultNavigation(configurationPath), handlers.Index)
  userVault.GET("/secrets", handlers.List)
  userVault.POST("", middleware.ParseSecretForm(), handlers.Create)
  userVault.PUT("/:id", middleware.ParseSecretForm(), handlers.Edit)
  userVault.DELETE("/:id", handlers.Delete)

  router.POST("/login", authLimit.Limit(), handlers.Login(configurationPath, usersDirectory, users))
  router.GET("/activate", handlers.ActivationForm)
  router.POST("/activate", authLimit.Limit(), handlers.Activate(usersDirectory))

  router.GET("/", legacyLimit.LimitCredentials(), func(c *gin.Context) {
    if _, ok := users.Current(c); ok {
      c.Redirect(303, "/vaults")
      return
    }
    // A new tab or refreshed document has no in-memory tab token. Show the
    // login form without clearing the cookie used by a different open tab.
    if c.GetHeader("X-Credentials") == "" {
      c.HTML(http.StatusUnauthorized, templates.Path("login"), gin.H{
        "sessionMaxAgeInSeconds": session.MaxAgeInSeconds,
        "csrfToken": middleware.CsrfToken(sessions.Default(c)),
        "authPage": true,
      })
      return
    }
    middleware.Authenticated(configurationPath)(c)
    if c.IsAborted() {
      return
    }
    handlers.Index(c)
  })

  authenticated := router.Group("", legacyLimit.LimitCredentials(), middleware.Authenticated(configurationPath))
  authenticated.GET("/secrets", handlers.List)
  authenticated.POST("/secrets", middleware.ParseSecretForm(), handlers.Create)
  authenticated.PUT("/secrets/:id", middleware.ParseSecretForm(), handlers.Edit)
  authenticated.DELETE("/secrets/:id", handlers.Delete)
}

func initTemplates() *template.Template {
  if templates, err := templates.Create(); err != nil {
    panic(err)
  } else {
    return templates
  }
}

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

func Create(configurationPath, membersDirectory string, prodModeEnabled bool) *gin.Engine {
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
  initRoutes(router, configurationPath, membersDirectory, session.NewMemberSessions())

  return router
}

func initRoutes(router *gin.Engine, configurationPath, membersDirectory string, members *session.MemberSessions) {
  router.POST("/logout", handlers.Logout(members))
  memberRoutes := router.Group("", func(c *gin.Context) {
    memberSession, ok := members.Current(c)
    if !ok {
      c.Redirect(303, "/")
      c.Abort()
      return
    }
    c.Set("memberSession", memberSession)
  })
  memberRoutes.GET("/settings", handlers.Settings)
  memberRoutes.POST("/settings/password", handlers.ChangeMemberPassword(membersDirectory, members))
  memberRoutes.GET("/vaults", handlers.Vaults(configurationPath))
  memberVault := memberRoutes.Group("/vaults/:alias", middleware.VaultAccess(configurationPath))
  memberVault.GET("", handlers.Index)
  memberVault.GET("/secrets", handlers.List)
  memberVault.POST("", handlers.Create)
  memberVault.PUT("/:id", handlers.Edit)
  memberVault.DELETE("/:id", handlers.Delete)

  router.POST("/login", handlers.Login(configurationPath, membersDirectory, members))
  router.GET("/activate", handlers.ActivationForm)
  router.POST("/activate", handlers.Activate(membersDirectory))

  router.GET("/", func(c *gin.Context) {
    if _, ok := members.Current(c); ok {
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

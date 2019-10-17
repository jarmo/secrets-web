package handlers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets-web/templates"
  "github.com/jarmo/secrets-web/redirect"
)

func Index(c *gin.Context) {
  c.HTML(http.StatusOK, templates.Path("index"), gin.H{
    "message": redirect.Message(c),
  })
}


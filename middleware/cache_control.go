package middleware

import (
  "path/filepath"
  "github.com/gin-gonic/gin"
)

var excludedExtensions = []string{".js", ".css", ".png", ".map"}

func CacheControl() gin.HandlerFunc {
  return func(c *gin.Context) {
    resourceExtension := filepath.Ext(c.Request.URL.String())
    if !contains(excludedExtensions, resourceExtension) {
      c.Writer.Header().Set("Cache-Control", "no-store, max-age=0")
    }
  }
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

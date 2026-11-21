package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Cap writes before parsing multipart or form data into memory.
const maxRequestBodySize int64 = 8 << 20

func RequestSize() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			if c.Request.ContentLength > maxRequestBodySize {
				c.AbortWithStatus(http.StatusRequestEntityTooLarge)
				return
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBodySize)
		}
		c.Next()
	}
}

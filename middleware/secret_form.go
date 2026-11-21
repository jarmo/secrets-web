package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ParseSecretForm checks parsing errors before a handler can accidentally save
// empty values after a malformed or oversized upload. Gin's PostForm helper
// otherwise discards ParseForm/ParseMultipartForm errors.
func ParseSecretForm() gin.HandlerFunc {
	return func(c *gin.Context) {
		var err error
		switch c.ContentType() {
		case "application/x-www-form-urlencoded":
			err = c.Request.ParseForm()
		case "multipart/form-data":
			err = c.Request.ParseMultipartForm(1 << 20)
		default:
			c.AbortWithStatus(http.StatusUnsupportedMediaType)
			return
		}
		if err != nil {
			status := http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			c.AbortWithStatus(status)
			return
		}
		c.Next()
	}
}

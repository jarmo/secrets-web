package redirect

import (
	"net/http"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func WithMessage(c *gin.Context, path string, message string) {
	session := sessions.Default(c)
	session.AddFlash(message)
	session.Save()
	redirect(c, path)
}

func Message(c *gin.Context) interface{} {
	session := sessions.Default(c)
	if flashes := session.Flashes(); len(flashes) > 0 {
		message := flashes[0].(string)
		session.Save()
		return message
	} else {
		return nil
	}
}

func redirect(c *gin.Context, path string) {
	c.Redirect(http.StatusSeeOther, path)
	c.AbortWithStatus(http.StatusSeeOther)
}

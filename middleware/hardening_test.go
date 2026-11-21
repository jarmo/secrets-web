package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthLimiterIgnoresSpoofedForwardedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/login", NewAuthLimiter().Limit(), func(c *gin.Context) { c.Status(http.StatusUnauthorized) })
	for i := 0; i < authMaxAttempts; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('A'+i)))
		response := httptest.NewRecorder()
		r.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("Attempt %d: %d", i, response.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "127.0.0.1:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	response := httptest.NewRecorder()
	r.ServeHTTP(response, req)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("Limit bypassed: %d", response.Code)
	}
}

func TestCacheControlNeverCachesDynamicURLs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CacheControl())
	r.GET("/secrets", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/public/test.js", func(c *gin.Context) { c.Status(http.StatusOK) })
	for _, path := range []string{"/secrets?file=test.js", "/secrets"} {
		response := httptest.NewRecorder()
		r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("Unprotected %s", path)
		}
	}
}

func TestRequestSizeRejectsKnownOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestSize())
	r.POST("/secret", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodPost, "/secret", strings.NewReader("a"))
	req.ContentLength = maxRequestBodySize + 1
	response := httptest.NewRecorder()
	r.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Got %d", response.Code)
	}
}

func TestSecretFormRejectsChunkedOversize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestSize())
	r.POST("/secret", ParseSecretForm(), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodPost, "/secret", strings.NewReader("value="+strings.Repeat("x", int(maxRequestBodySize))))
	req.ContentLength = -1 // Do not trust Content-Length to be present.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	r.ServeHTTP(response, req)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Oversize form was accepted: %d", response.Code)
	}
}

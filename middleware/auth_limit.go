package middleware

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthLimiter bounds expensive password checks, including attempts made with
// different usernames. It uses the TCP peer rather than untrusted X-Forwarded-For.
// This in-memory limiter is per web process; a reverse proxy should also rate
// limit requests when the service is exposed to the Internet.
type AuthLimiter struct {
	mu          sync.Mutex
	clients     map[string]authWindow
	active      chan struct{}
	maxAttempts int
}

type authWindow struct {
	start    time.Time
	attempts int
}

const (
	authWindowDuration = time.Minute
	authMaxAttempts    = 20
	legacyMaxAttempts  = 120
	authMaxClients     = 10000
	authMaxConcurrent  = 4
)

func NewAuthLimiter() *AuthLimiter {
	return &AuthLimiter{clients: make(map[string]authWindow), active: make(chan struct{}, authMaxConcurrent), maxAttempts: authMaxAttempts}
}

func NewLegacyAuthLimiter() *AuthLimiter {
	limiter := NewAuthLimiter()
	limiter.maxAttempts = legacyMaxAttempts
	return limiter
}

func (limiter *AuthLimiter) LimitCredentials() gin.HandlerFunc {
	limited := limiter.Limit()
	return func(c *gin.Context) {
		if c.GetHeader("X-Credentials") == "" {
			c.Next()
			return
		}
		limited(c)
	}
}

func (limiter *AuthLimiter) Limit() gin.HandlerFunc {
	return func(c *gin.Context) {
		peer := c.Request.RemoteAddr
		if ip, _, err := net.SplitHostPort(peer); err == nil {
			peer = ip
		}
		now := time.Now()
		limiter.mu.Lock()
		entry, found := limiter.clients[peer]
		if !found || now.Sub(entry.start) >= authWindowDuration {
			if !found && len(limiter.clients) >= authMaxClients {
				for ip, existing := range limiter.clients {
					if now.Sub(existing.start) >= authWindowDuration {
						delete(limiter.clients, ip)
					}
				}
			}
			if !found && len(limiter.clients) >= authMaxClients {
				limiter.mu.Unlock()
				c.AbortWithStatus(http.StatusTooManyRequests)
				return
			}
			entry = authWindow{start: now}
		}
		if entry.attempts >= limiter.maxAttempts {
			retry := int(authWindowDuration.Seconds()-now.Sub(entry.start).Seconds()) + 1
			limiter.mu.Unlock()
			c.Header("Retry-After", strconv.Itoa(retry))
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		entry.attempts++
		limiter.clients[peer] = entry
		limiter.mu.Unlock()

		// Never queue unlimited Argon2 checks: return 429 at capacity.
		select {
		case limiter.active <- struct{}{}:
			defer func() { <-limiter.active }()
			c.Next()
		default:
			c.Header("Retry-After", "1")
			c.AbortWithStatus(http.StatusTooManyRequests)
		}
	}
}

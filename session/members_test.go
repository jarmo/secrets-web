package session

import (
  "crypto/ecdh"
  "crypto/rand"
  "net/http"
  "net/http/httptest"
  "strings"
  "testing"
  "time"

  "github.com/gin-gonic/gin"
)

func TestMemberSessionsRenewAndExpire(t *testing.T) {
  privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    t.Fatal(err)
  }
  store := NewMemberSessions()
  router := gin.New()
  router.Use(CreateCookie(false))
  router.GET("/login", func(c *gin.Context) {
    if err := store.Login(c, "bob", privateKey); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    c.Status(http.StatusNoContent)
  })
  router.GET("/current", func(c *gin.Context) {
    if _, ok := store.Current(c); !ok {
      c.Status(http.StatusUnauthorized)
      return
    }
    c.Status(http.StatusNoContent)
  })

  request := func(path, cookie string) *httptest.ResponseRecorder {
    t.Helper()
    call := httptest.NewRequest("GET", path, nil)
    if cookie != "" {
      call.Header.Set("Cookie", cookie)
    }
    response := httptest.NewRecorder()
    router.ServeHTTP(response, call)
    return response
  }

  login := request("/login", "")
  if login.Code != http.StatusNoContent {
    t.Fatalf("Login status: %d", login.Code)
  }
  oldCookie := login.Header().Get("Set-Cookie")
  var id string
  store.mutex.Lock()
  for activeID, memberSession := range store.active {
    id = activeID
    memberSession.expiresAt = time.Now().Add(time.Second)
    store.active[activeID] = memberSession
  }
  store.mutex.Unlock()

  refreshed := request("/current", oldCookie)
  if refreshed.Code != http.StatusNoContent {
    t.Fatalf("Current session status: %d", refreshed.Code)
  }
  if !strings.Contains(refreshed.Header().Get("Set-Cookie"), "Max-Age=") {
    t.Fatal("Cookie lifetime was not refreshed")
  }
  store.mutex.Lock()
  renewedExpiry := store.active[id].expiresAt
  store.mutex.Unlock()
  if renewedExpiry.Before(time.Now().Add(14 * time.Minute)) {
    t.Fatal("Active session lifetime was not extended")
  }

  store.mutex.Lock()
  expired := store.active[id]
  expired.expiresAt = time.Now().Add(-time.Second)
  store.active[id] = expired
  store.mutex.Unlock()
  if response := request("/current", refreshed.Header().Get("Set-Cookie")); response.Code != http.StatusUnauthorized {
    t.Fatalf("Expired session accepted: %d", response.Code)
  }
}

func TestMemberSessionsLogoutInvalidatesAll(t *testing.T) {
  privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    t.Fatal(err)
  }
  store := NewMemberSessions()
  router := gin.New()
  router.Use(CreateCookie(false))
  router.GET("/login", func(c *gin.Context) {
    if err := store.Login(c, "bob", privateKey); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    c.Status(http.StatusNoContent)
  })
  router.GET("/logout", func(c *gin.Context) {
    if err := store.Logout(c); err != nil {
      c.Status(http.StatusInternalServerError)
      return
    }
    c.Status(http.StatusNoContent)
  })
  response := httptest.NewRecorder()
  router.ServeHTTP(response, httptest.NewRequest("GET", "/login", nil))
  cookie := response.Header().Get("Set-Cookie")
  store.mutex.Lock()
  store.active["another-session-for-bob"] = MemberSession{Username: "bob", PrivateKey: privateKey, expiresAt: time.Now().Add(time.Minute)}
  store.active["alice-session"] = MemberSession{Username: "alice", PrivateKey: privateKey, expiresAt: time.Now().Add(time.Minute)}
  store.mutex.Unlock()
  logoutRequest := httptest.NewRequest("GET", "/logout", nil)
  logoutRequest.Header.Set("Cookie", cookie)
  logout := httptest.NewRecorder()
  router.ServeHTTP(logout, logoutRequest)
  if logout.Code != http.StatusNoContent {
    t.Fatalf("Logout status: %d", logout.Code)
  }
  store.mutex.Lock()
  defer store.mutex.Unlock()
  if len(store.active) != 1 || store.active["alice-session"].Username != "alice" {
    t.Fatalf("Logout revoked the wrong sessions: %v", store.active)
  }
}

package session

import (
  "crypto/ecdh"
  "net/http"
  "net/http/httptest"
  "path/filepath"
  "strings"
  "testing"
  "time"

  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/user"
)

func TestUserSessionsRenewAndExpire(t *testing.T) {
  directory, account, privateKey := newSessionTestAccount(t)
  store := NewUserSessions(directory)
  router := gin.New()
  router.Use(CreateCookie(false))
  router.GET("/login", func(c *gin.Context) {
    if err := store.Login(c, account, privateKey); err != nil {
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
  for activeID, userSession := range store.active {
    id = activeID
    userSession.expiresAt = time.Now().Add(time.Second)
    store.active[activeID] = userSession
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

func TestUserSessionsLogoutInvalidatesAll(t *testing.T) {
  directory, account, privateKey := newSessionTestAccount(t)
  store := NewUserSessions(directory)
  router := gin.New()
  router.Use(CreateCookie(false))
  router.GET("/login", func(c *gin.Context) {
    if err := store.Login(c, account, privateKey); err != nil {
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
  store.active["another-session-for-bob"] = UserSession{Username: "bob", PrivateKey: privateKey, expiresAt: time.Now().Add(time.Minute)}
  store.active["alice-session"] = UserSession{Username: "alice", PrivateKey: privateKey, expiresAt: time.Now().Add(time.Minute)}
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

func newSessionTestAccount(t *testing.T) (string, user.User, *ecdh.PrivateKey) {
  t.Helper()
  directory := filepath.Join(t.TempDir(), "users")
  if err := user.Register(directory, "bob", []byte("original password 123")); err != nil {
    t.Fatal(err)
  }
  account, privateKey, err := user.Authenticate(directory, "bob", []byte("original password 123"))
  if err != nil {
    t.Fatal(err)
  }
  return directory, account, privateKey
}

func TestUserSessionInvalidatedAfterPasswordChange(t *testing.T) {
  directory, account, privateKey := newSessionTestAccount(t)
  store := NewUserSessions(directory)
  router := gin.New()
  router.Use(CreateCookie(false))
  router.GET("/login", func(c *gin.Context) {
    if err := store.Login(c, account, privateKey); err != nil {
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

  login := httptest.NewRecorder()
  router.ServeHTTP(login, httptest.NewRequest("GET", "/login", nil))
  if login.Code != http.StatusNoContent {
    t.Fatalf("Login status: %d", login.Code)
  }
  cookie := login.Header().Get("Set-Cookie")
  if err := user.ChangePassword(directory, "bob", []byte("original password 123"), []byte("new password 456")); err != nil {
    t.Fatal(err)
  }
  request := httptest.NewRequest("GET", "/current", nil)
  request.Header.Set("Cookie", cookie)
  response := httptest.NewRecorder()
  router.ServeHTTP(response, request)
  if response.Code != http.StatusUnauthorized {
    t.Fatalf("Password change left session active: %d", response.Code)
  }
  store.mutex.Lock()
  remaining := len(store.active)
  store.mutex.Unlock()
  if remaining != 0 {
    t.Fatal("Invalidated session remained in memory")
  }
}

func TestUserSessionInvalidatedAfterAccountDeletion(t *testing.T) {
  directory, account, privateKey := newSessionTestAccount(t)
  store := NewUserSessions(directory)
  router := gin.New()
  router.Use(CreateCookie(false))
  router.GET("/login", func(c *gin.Context) {
    if err := store.Login(c, account, privateKey); err != nil {
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
  login := httptest.NewRecorder()
  router.ServeHTTP(login, httptest.NewRequest("GET", "/login", nil))
  if login.Code != http.StatusNoContent {
    t.Fatalf("Login status: %d", login.Code)
  }
  if err := user.Destroy(directory, "bob"); err != nil {
    t.Fatal(err)
  }
  request := httptest.NewRequest("GET", "/current", nil)
  request.Header.Set("Cookie", login.Header().Get("Set-Cookie"))
  response := httptest.NewRecorder()
  router.ServeHTTP(response, request)
  if response.Code != http.StatusUnauthorized {
    t.Fatalf("Deleted account left session active: %d", response.Code)
  }
}

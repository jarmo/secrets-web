package session

import (
  "crypto/ecdh"
  "crypto/rand"
  "encoding/base64"
  "errors"
  "sync"
  "time"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
)

type UserSession struct {
  Username string
  PrivateKey *ecdh.PrivateKey
  expiresAt time.Time
}

type UserSessions struct {
  mutex sync.Mutex
  active map[string]UserSession
}

func NewUserSessions() *UserSessions {
  return &UserSessions{active: make(map[string]UserSession)}
}

func (store *UserSessions) Login(c *gin.Context, username string, privateKey *ecdh.PrivateKey) error {
  if privateKey == nil {
    return errors.New("Missing user key")
  }
  idBytes := make([]byte, 32)
  if _, err := rand.Read(idBytes); err != nil {
    return err
  }
  id := base64.RawURLEncoding.EncodeToString(idBytes)
  cookie := sessions.Default(c)
  cookie.Set("userSession", id)
  if err := cookie.Save(); err != nil {
    return err
  }

  store.mutex.Lock()
  defer store.mutex.Unlock()
  now := time.Now()
  for existingID, existing := range store.active {
    if !now.Before(existing.expiresAt) || existing.Username == username {
      delete(store.active, existingID)
    }
  }
  store.active[id] = UserSession{Username: username, PrivateKey: privateKey, expiresAt: now.Add(MaxAgeInSeconds * time.Second)}
  return nil
}

func (store *UserSessions) Current(c *gin.Context) (UserSession, bool) {
  cookie := sessions.Default(c)
  id, ok := cookie.Get("userSession").(string)
  if !ok || id == "" {
    return UserSession{}, false
  }
  store.mutex.Lock()
  defer store.mutex.Unlock()
  userSession, found := store.active[id]
  if !found {
    return UserSession{}, false
  }
  now := time.Now()
  if !now.Before(userSession.expiresAt) {
    delete(store.active, id)
    return UserSession{}, false
  }
  cookie.Set("userSession", id)
  if err := cookie.Save(); err != nil {
    return UserSession{}, false
  }
  userSession.expiresAt = now.Add(MaxAgeInSeconds * time.Second)
  store.active[id] = userSession
  return userSession, true
}

func (store *UserSessions) Logout(c *gin.Context) error {
  cookie := sessions.Default(c)
  if id, ok := cookie.Get("userSession").(string); ok {
    store.mutex.Lock()
    if userSession, found := store.active[id]; found {
      for existingID, existing := range store.active {
        if existing.Username == userSession.Username {
          delete(store.active, existingID)
        }
      }
    }
    store.mutex.Unlock()
  }
  cookie.Delete("userSession")
  return cookie.Save()
}

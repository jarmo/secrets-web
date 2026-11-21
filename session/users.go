package session

import (
  "crypto/ecdh"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "encoding/json"
  "errors"
  "sync"
  "time"

  "github.com/gin-contrib/sessions"
  "github.com/gin-gonic/gin"
  "github.com/jarmo/secrets/user"
)

type UserSession struct {
  Username string
  PrivateKey *ecdh.PrivateKey
  identityFingerprint [sha256.Size]byte
  expiresAt time.Time
}

type UserSessions struct {
  mutex sync.Mutex
  active map[string]UserSession
  usersDirectory string
}

func NewUserSessions(usersDirectory string) *UserSessions {
  return &UserSessions{active: make(map[string]UserSession), usersDirectory: usersDirectory}
}

func (store *UserSessions) Login(c *gin.Context, account user.User, privateKey *ecdh.PrivateKey) error {
  if privateKey == nil {
    return errors.New("Missing user key")
  }
  fingerprint, err := userFingerprint(account)
  if err != nil {
    return err
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
    if !now.Before(existing.expiresAt) || existing.Username == account.Username {
      delete(store.active, existingID)
    }
  }
  store.active[id] = UserSession{Username: account.Username, PrivateKey: privateKey, identityFingerprint: fingerprint, expiresAt: now.Add(MaxAgeInSeconds * time.Second)}
  return nil
}

func (store *UserSessions) Current(c *gin.Context) (UserSession, bool) {
  return store.current(c, true)
}

func (store *UserSessions) Valid(c *gin.Context) bool {
  _, ok := store.Inspect(c)
  return ok
}

func (store *UserSessions) Inspect(c *gin.Context) (UserSession, bool) {
  return store.current(c, false)
}

func (store *UserSessions) current(c *gin.Context, renew bool) (UserSession, bool) {
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
  account, err := user.Load(store.usersDirectory, userSession.Username)
  if err != nil {
    delete(store.active, id)
    cookie.Delete("userSession")
    cookie.Save()
    return UserSession{}, false
  }
  fingerprint, err := userFingerprint(account)
  if err != nil || fingerprint != userSession.identityFingerprint {
    delete(store.active, id)
    cookie.Delete("userSession")
    cookie.Save()
    return UserSession{}, false
  }
  if renew {
    cookie.Set("userSession", id)
    if err := cookie.Save(); err != nil {
      return UserSession{}, false
    }
    userSession.expiresAt = now.Add(MaxAgeInSeconds * time.Second)
    store.active[id] = userSession
  }
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

func userFingerprint(account user.User) ([sha256.Size]byte, error) {
  data, err := json.Marshal(account)
  if err != nil {
    return [sha256.Size]byte{}, err
  }
  return sha256.Sum256(data), nil
}

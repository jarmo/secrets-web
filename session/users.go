package session

import (
  "crypto/ecdh"
  "crypto/rand"
  "crypto/sha256"
  "crypto/subtle"
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
  tabTokenHash [sha256.Size]byte
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
  tokenHash, ok := tabTokenHash(c.GetHeader("X-Tab-Token"))
  if !ok {
    return errors.New("Missing or invalid tab authorization")
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
  now := time.Now()
  for existingID, existing := range store.active {
    if !now.Before(existing.expiresAt) || existing.Username == account.Username {
      delete(store.active, existingID)
    }
  }
  store.active[id] = UserSession{Username: account.Username, PrivateKey: privateKey, identityFingerprint: fingerprint, tabTokenHash: tokenHash, expiresAt: now.Add(MaxAgeInSeconds * time.Second)}
  store.mutex.Unlock()
  // Erase expired private keys even if the browser never contacts us again.
  store.scheduleCleanup(id, now.Add(MaxAgeInSeconds * time.Second))
  return nil
}

func (store *UserSessions) scheduleCleanup(id string, deadline time.Time) {
  time.AfterFunc(time.Until(deadline), func() {
    store.mutex.Lock()
    active, found := store.active[id]
    if !found {
      store.mutex.Unlock()
      return
    }
    if !time.Now().Before(active.expiresAt) {
      delete(store.active, id)
      store.mutex.Unlock()
      return
    }
    nextExpiry := active.expiresAt
    store.mutex.Unlock()
    store.scheduleCleanup(id, nextExpiry)
  })
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
  tokenHash, valid := tabTokenHash(c.GetHeader("X-Tab-Token"))
  if !valid || subtle.ConstantTimeCompare(tokenHash[:], userSession.tabTokenHash[:]) != 1 {
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
      tokenHash, valid := tabTokenHash(c.GetHeader("X-Tab-Token"))
      if !valid || subtle.ConstantTimeCompare(tokenHash[:], userSession.tabTokenHash[:]) != 1 {
        store.mutex.Unlock()
        return errors.New("Invalid tab authorization")
      }
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

func tabTokenHash(value string) ([sha256.Size]byte, bool) {
  if len(value) != 43 {
    return [sha256.Size]byte{}, false
  }
  decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
  if err != nil || len(decoded) != 32 {
    return [sha256.Size]byte{}, false
  }
  return sha256.Sum256(decoded), true
}

func userFingerprint(account user.User) ([sha256.Size]byte, error) {
  data, err := json.Marshal(account)
  if err != nil {
    return [sha256.Size]byte{}, err
  }
  return sha256.Sum256(data), nil
}

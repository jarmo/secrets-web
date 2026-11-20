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

type MemberSession struct {
  Username string
  PrivateKey *ecdh.PrivateKey
  expiresAt time.Time
}

type MemberSessions struct {
  mutex sync.Mutex
  active map[string]MemberSession
}

func NewMemberSessions() *MemberSessions {
  return &MemberSessions{active: make(map[string]MemberSession)}
}

func (store *MemberSessions) Login(c *gin.Context, username string, privateKey *ecdh.PrivateKey) error {
  if privateKey == nil {
    return errors.New("Missing member key")
  }
  idBytes := make([]byte, 32)
  if _, err := rand.Read(idBytes); err != nil {
    return err
  }
  id := base64.RawURLEncoding.EncodeToString(idBytes)
  cookie := sessions.Default(c)
  cookie.Set("memberSession", id)
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
  store.active[id] = MemberSession{Username: username, PrivateKey: privateKey, expiresAt: now.Add(MaxAgeInSeconds * time.Second)}
  return nil
}

func (store *MemberSessions) Current(c *gin.Context) (MemberSession, bool) {
  cookie := sessions.Default(c)
  id, ok := cookie.Get("memberSession").(string)
  if !ok || id == "" {
    return MemberSession{}, false
  }
  store.mutex.Lock()
  defer store.mutex.Unlock()
  memberSession, found := store.active[id]
  if !found {
    return MemberSession{}, false
  }
  now := time.Now()
  if !now.Before(memberSession.expiresAt) {
    delete(store.active, id)
    return MemberSession{}, false
  }
  cookie.Set("memberSession", id)
  if err := cookie.Save(); err != nil {
    return MemberSession{}, false
  }
  memberSession.expiresAt = now.Add(MaxAgeInSeconds * time.Second)
  store.active[id] = memberSession
  return memberSession, true
}

func (store *MemberSessions) Logout(c *gin.Context) error {
  cookie := sessions.Default(c)
  if id, ok := cookie.Get("memberSession").(string); ok {
    store.mutex.Lock()
    if memberSession, found := store.active[id]; found {
      for existingID, existing := range store.active {
        if existing.Username == memberSession.Username {
          delete(store.active, existingID)
        }
      }
    }
    store.mutex.Unlock()
  }
  cookie.Delete("memberSession")
  return cookie.Save()
}

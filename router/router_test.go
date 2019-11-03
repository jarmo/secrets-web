package router

import (
  "encoding/base64"
  "io/ioutil"
  "net/http"
  "net/http/httptest"
  "os"
  "strings"
  "fmt"
  "testing"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/jarmo/secrets/secret"
  "github.com/jarmo/secrets/storage"
  "github.com/jarmo/secrets/storage/path"
)

const csrfToken = "csrf-token"
const user = "user"
const password = "password"

func Test_Router(t *testing.T) {
  configPath := tempFilePath(t, "test-secrets-config")
  defer os.Remove(configPath)

  vaultPath := tempFilePath(t, "test-secrets-vault")
  defer os.Remove(vaultPath)

  path.Store(configPath, vaultPath, user)

  initialSecrets := make([]secret.Secret, 0)
  storage.Write(vaultPath, []byte(password), initialSecrets)

  gin.SetMode(gin.ReleaseMode)
  router := Create(configPath, false)
  router.GET("/init-csrf-token", func(c *gin.Context) {
    session := sessions.Default(c)
    session.Set("csrfToken", csrfToken)
    session.Save()
    c.String(200, "ok")
  })

  req, _ := http.NewRequest("GET", "/init-csrf-token", nil)
  res := httptest.NewRecorder()
  router.ServeHTTP(res, req)
  assertCode(t, 200, res.Code)
  assertBody(t, res.Body.String(), "ok")
  session := res.Header().Get("Set-Cookie")

  t.Run("GET /secrets => No authenticated header", func(t *testing.T) {
    req, _ := http.NewRequest("GET", "/secrets", nil)
    res := httptest.NewRecorder()
    router.ServeHTTP(res, req)

    assertCode(t, 401, res.Code)
    assertBody(t, res.Body.String(), "User")
    assertBody(t, res.Body.String(), "Password")
  })

  t.Run("GET /secrets => Authenticated", func(t *testing.T) {
    req, _ := http.NewRequest("GET", "/secrets", nil)
    authenticate(req, user, password)
    res := httptest.NewRecorder()
    router.ServeHTTP(res, req)

    assertCode(t, 200, res.Code)
    assertBody(t, res.Body.String(), "Filter")
  })

  t.Run("GET /secrets => Authenticated with invalid user", func(t *testing.T) {
    req, _ := http.NewRequest("GET", "/secrets", nil)
    authenticate(req, "invalid-user", password)
    res := httptest.NewRecorder()
    router.ServeHTTP(res, req)

    assertCode(t, 401, res.Code)
    assertBody(t, res.Body.String(), "User")
    assertBody(t, res.Body.String(), "Password")
  })

  t.Run("GET /secrets => Authenticated with invalid password", func(t *testing.T) {
    req, _ := http.NewRequest("GET", "/secrets", nil)
    authenticate(req, user, "invalid-password")
    res := httptest.NewRecorder()
    router.ServeHTTP(res, req)

    assertCode(t, 401, res.Code)
    assertBody(t, res.Body.String(), "User")
    assertBody(t, res.Body.String(), "Password")
  })

  t.Run("GET /secrets => Secret not found", func(t *testing.T) {
    secret1 := secret.New("secret-1-name", "secret-1-value")
    secret2 := secret.New("secret-2-name", "secret-2-value")
    secrets := []secret.Secret{secret1, secret2}
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "GET", "/secrets?filter=no-secret", "", session)

    assertCode(t, 200, res.Code)
    assertNotInBody(t, res.Body.String(), "secret-1-name")
    assertNotInBody(t, res.Body.String(), "secret-1-value")
    assertNotInBody(t, res.Body.String(), "secret-2-name")
    assertNotInBody(t, res.Body.String(), "secret-2-value")
    assertBody(t, res.Body.String(), "Filter")
  })

  t.Run("GET /secrets => Secret found", func(t *testing.T) {
    secret1 := secret.New("secret-1-name", "secret-1-value")
    secret2 := secret.New("secret-2-name", "secret-2-value")
    secrets := []secret.Secret{secret1, secret2}
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "GET", "/secrets?filter=secret-2-name", "", session)

    assertCode(t, 200, res.Code)
    assertNotInBody(t, res.Body.String(), "secret-1-name")
    assertNotInBody(t, res.Body.String(), "secret-1-value")
    assertBody(t, res.Body.String(), "secret-2-name")
    assertBody(t, res.Body.String(), "secret-2-value")
    assertBody(t, res.Body.String(), "Filter")
  })

  t.Run("POST /secrets => No CSRF header", func(t *testing.T) {
    req, _ := http.NewRequest("POST", "/secrets", nil)
    authenticate(req, user, password)
    res := httptest.NewRecorder()
    router.ServeHTTP(res, req)

    assertCode(t, 412, res.Code)
    assertBody(t, res.Body.String(), "User")
    assertBody(t, res.Body.String(), "Password")
  })

  t.Run("POST /secrets => Invalid CSRF header", func(t *testing.T) {
    req, _ := http.NewRequest("POST", "/secrets", nil)
    authenticate(req, user, password)
    req.Header.Set("Cookie", session)
    req.Header.Set("X-Csrf-Token", "invalid-token")
    res := httptest.NewRecorder()
    router.ServeHTTP(res, req)

    assertCode(t, 412, res.Code)
    assertBody(t, res.Body.String(), "User")
    assertBody(t, res.Body.String(), "Password")
  })

  t.Run("POST /secrets", func(t *testing.T) {
    secrets := make([]secret.Secret, 0)
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "POST", "/secrets", "name=new-secret-name&value=new-secret-value", session)

    assertCode(t, 303, res.Code)
    secrets, err := storage.Read(vaultPath, []byte(password))

    if err != nil {
      t.Fatal(err)
    }

    if len(secrets) != 1 {
      t.Fatalf("Expected to have one secret, but got %d", len(secrets))
    }

    actualSecret := secrets[0]
    expectedSecret := secret.Secret{Id: actualSecret.Id, Name: "new-secret-name", Value: "new-secret-value"}

    if fmt.Sprintf("%v", actualSecret) != fmt.Sprintf("%v", expectedSecret) {
      t.Fatalf("Expected secret to be %s, but got %s", expectedSecret, actualSecret)
    }
  })

  t.Run("PUT /secrets/:id => Unknown id", func(t *testing.T) {
    secrets := make([]secret.Secret, 0)
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "PUT", "/secrets/3ea1cd70-da37-444a-bfc1-f9ca70881f96", "name=new-secret-name&value=new-secret-value", session)

    assertCode(t, 200, res.Code)
    assertBody(t, res.Body.String(), "Secret by specified id not found!")
    secrets, err := storage.Read(vaultPath, []byte(password))

    if err != nil {
      t.Fatal(err)
    }

    if len(secrets) != 0 {
      t.Fatalf("Expected to have no secrets, but got %d", len(secrets))
    }
  })

  t.Run("PUT /secrets/:id", func(t *testing.T) {
    existingSecret := secret.New("secret-1-name", "secret-1-value")
    secrets := []secret.Secret{existingSecret}
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "PUT", "/secrets/" + existingSecret.Id.String(), "name=new-secret-name&value=new-secret-value", session)

    assertCode(t, 303, res.Code)
    secrets, err := storage.Read(vaultPath, []byte(password))

    if err != nil {
      t.Fatal(err)
    }

    if len(secrets) != 1 {
      t.Fatalf("Expected to have one secret, but got %d", len(secrets))
    }

    actualSecret := secrets[0]
    expectedSecret := secret.Secret{Id: existingSecret.Id, Name: "new-secret-name", Value: "new-secret-value"}

    if fmt.Sprintf("%v", actualSecret) != fmt.Sprintf("%v", expectedSecret) {
      t.Fatalf("Expected secret to be %s, but got %s", expectedSecret, actualSecret)
    }
  })

  t.Run("DELETE /secrets/:id => Unknown id", func(t *testing.T) {
    secrets := make([]secret.Secret, 0)
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "DELETE", "/secrets/3ea1cd70-da37-444a-bfc1-f9ca70881f96", "", session)

    assertCode(t, 200, res.Code)
    assertBody(t, res.Body.String(), "Secret by specified id not found!")
    secrets, err := storage.Read(vaultPath, []byte(password))

    if err != nil {
      t.Fatal(err)
    }

    if len(secrets) != 0 {
      t.Fatalf("Expected to have no secrets, but got %d", len(secrets))
    }
  })

  t.Run("DELETE /secrets/:id", func(t *testing.T) {
    existingSecret := secret.New("secret-1-name", "secret-1-value")
    secrets := []secret.Secret{existingSecret}
    storage.Write(vaultPath, []byte(password), secrets[:])

    res := request(router, "DELETE", "/secrets/" + existingSecret.Id.String(), "", session)

    assertCode(t, 303, res.Code)
    secrets, err := storage.Read(vaultPath, []byte(password))

    if err != nil {
      t.Fatal(err)
    }

    if len(secrets) != 0 {
      t.Fatalf("Expected to have no secrets, but got %d", len(secrets))
    }
  })
}

func request(router *gin.Engine, method, path, body, session string) *httptest.ResponseRecorder {
  req, _ := http.NewRequest(method, path, strings.NewReader(body))
  authenticate(req, user, password)
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  req.Header.Set("Cookie", session)
  req.Header.Set("X-Csrf-Token", csrfToken)

  res := httptest.NewRecorder()
  router.ServeHTTP(res, req)

  return res
}


func authenticate(req *http.Request, user, password string) {
  req.Header.Set("X-Credentials", base64.StdEncoding.EncodeToString([]byte(user + ":" + password)))
}

func assertCode(t *testing.T, expected, actual int) {
  if actual != expected {
    t.Fatalf("Expected code to be '%v', but was '%v'", expected, actual)
  }
}

func assertBody(t *testing.T, body, needle string) {
  if !strings.Contains(body, needle) {
    t.Fatalf("Expected body '%v' to contain '%v', but didn't", body, needle)
  }
}

func assertNotInBody(t *testing.T, body, needle string) {
  if strings.Contains(body, needle) {
    t.Fatalf("Expected body '%v' not to contain '%v', but did", body, needle)
  }
}

func tempFilePath(t *testing.T, prefix string) string {
  path, err := ioutil.TempFile("", "test-secrets-vault")
  if err != nil {
    t.Fatal(err)
  }
  return path.Name()
}

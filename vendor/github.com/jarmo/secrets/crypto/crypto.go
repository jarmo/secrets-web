package crypto

import (
  "encoding/base64"
  "crypto/rand"
  "encoding/json"
  "errors"
  "fmt"
  "golang.org/x/crypto/argon2"
  "golang.org/x/crypto/nacl/secretbox"
  "github.com/jarmo/secrets/secret"
)

type argon2idParams struct {
  Time int
  Memory int
  Threads int
}

type Encrypted struct {
  Data string
  Nonce string
  Salt string
  Params map[string]int
}

func Encrypt(password []byte, secrets []secret.Secret) Encrypted {
  if encryptedSecretJSON, err := json.Marshal(secrets); err != nil {
    panic(err)
  } else {
    defer wipeShared(encryptedSecretJSON)
    salt := GenerateRandomBytes(32)
    time := 3
    memory := 64*1024
    threads := 4
    secretKey := argon2idSecretKey(password, salt, argon2idParams{Time: time, Memory: memory, Threads: threads})
    defer wipeShared(secretKey[:])
    var nonce [24]byte
    copy(nonce[:], GenerateRandomBytes(24))

    data := secretbox.Seal(nil, encryptedSecretJSON, &nonce, &secretKey)
    params := map[string]int{"Time": time, "Memory": memory, "Threads": threads}
    return Encrypted{
      Data: base64.StdEncoding.EncodeToString(data),
      Nonce: base64.StdEncoding.EncodeToString(nonce[:]),
      Salt: base64.StdEncoding.EncodeToString(salt),
      Params: params,
    }
  }
}

func Decrypt(password []byte, encryptedSecrets Encrypted) ([]secret.Secret, error) {
  params := encryptedSecrets.Params
  if params["Time"] < 1 || params["Time"] > 10 ||
    params["Memory"] < 8 || params["Memory"] > 256*1024 ||
    params["Threads"] < 1 || params["Threads"] > 16 ||
    params["Memory"] < 8*params["Threads"] {
    return nil, errors.New("Invalid vault format: unsupported Argon2id parameters")
  }

  salt, err := base64.StdEncoding.DecodeString(encryptedSecrets.Salt)
  if err != nil || len(salt) != 32 {
    return nil, errors.New("Invalid vault format: invalid salt")
  }
  data, err := base64.StdEncoding.DecodeString(encryptedSecrets.Data)
  if err != nil || len(data) < secretbox.Overhead {
    return nil, errors.New("Invalid vault format: invalid ciphertext")
  }
  nonceBytes, err := base64.StdEncoding.DecodeString(encryptedSecrets.Nonce)
  if err != nil || len(nonceBytes) != 24 {
    return nil, errors.New("Invalid vault format: invalid nonce")
  }

  secretKey := secretKey(password, salt, params)
  defer wipeShared(secretKey[:])
  var nonce [24]byte
  copy(nonce[:], nonceBytes)
  var decryptedSecrets []secret.Secret

  if decryptedSecretsJSON, ok := secretbox.Open(nil, data, &nonce, &secretKey); !ok {
    return make([]secret.Secret, 0), errors.New("Invalid vault password!")
  } else {
    defer wipeShared(decryptedSecretsJSON)
    if err := json.Unmarshal(decryptedSecretsJSON, &decryptedSecrets); err != nil {
      return nil, fmt.Errorf("Invalid vault format: invalid decrypted secrets: %w", err)
    }
  }

  return decryptedSecrets, nil
}

func GenerateRandomBytes(length int) []byte {
  result := make([]byte, length)
  _, err := rand.Read(result)
  if err != nil {
    panic(err)
  }

  return result
}

func secretKey(password, salt []byte, params map[string]int) [32]byte {
  return argon2idSecretKey(
    password,
    []byte(salt),
    argon2idParams{Time: params["Time"], Memory: params["Memory"], Threads: params["Threads"]},
  )
}

func argon2idSecretKey(password, salt []byte, params argon2idParams) [32]byte {
  keyLength := 32

  secretKeyBytes := argon2.IDKey(
    password,
    salt,
    uint32(params.Time),
    uint32(params.Memory),
    uint8(params.Threads),
    uint32(keyLength),
  )

  var secretKey [32]byte
  copy(secretKey[:], secretKeyBytes)
  wipeShared(secretKeyBytes)

  return secretKey
}


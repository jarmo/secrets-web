package crypto

import (
  "math"
  "encoding/base64"
  "crypto/rand"
  "encoding/json"
  "errors"
  "golang.org/x/crypto/scrypt"
  "golang.org/x/crypto/argon2"
  "golang.org/x/crypto/nacl/secretbox"
  "github.com/jarmo/secrets/v5/secret"
)

type scryptParams struct {
  N int
  R int
  P int
}

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
    salt := generateRandomBytes(32)
    time := 1
    memory := 64*1024
    threads := 4
    secretKey := argon2idSecretKey(password, salt, argon2idParams{Time: time, Memory: memory, Threads: threads})
    var nonce [24]byte
    copy(nonce[:], generateRandomBytes(24))

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
  salt, _ := base64.StdEncoding.DecodeString(encryptedSecrets.Salt)
  secretKey := secretKey(password, salt, encryptedSecrets.Params)
  data, _ := base64.StdEncoding.DecodeString(encryptedSecrets.Data)
  nonceBytes, _ := base64.StdEncoding.DecodeString(encryptedSecrets.Nonce)
  var nonce [24]byte
  copy(nonce[:], nonceBytes)
  var decryptedSecrets []secret.Secret

  if decryptedSecretsJSON, ok := secretbox.Open(nil, data, &nonce, &secretKey); !ok {
    return make([]secret.Secret, 0), errors.New("Invalid vault password!")
  } else if err := json.Unmarshal(decryptedSecretsJSON, &decryptedSecrets); err != nil {
    panic(err)
  }

  return decryptedSecrets, nil
}

func secretKey(password, salt []byte, params map[string]int) [32]byte {
  if _, hasValue := params["Time"]; hasValue {
    return argon2idSecretKey(
      password,
      []byte(salt),
      argon2idParams{Time: params["Time"], Memory: params["Memory"], Threads: params["Threads"]},
    )
  } else {
    return scryptSecretKey(
      password,
      []byte(salt),
      scryptParams{N: params["N"], R: params["R"], P: params["p"]},
    )
  }
}

func scryptSecretKey(password, salt []byte, params scryptParams) [32]byte {
  keyLength := 32

  secretKeyBytes, err := scrypt.Key(
    password,
    salt,
    int(math.Max(float64(params.N), 16384)),
    int(math.Max(float64(params.R), 8)),
    int(math.Max(float64(params.P), 2)),
    keyLength,
  )

  if err != nil {
    panic(err)
  }

  var secretKey [32]byte
  copy(secretKey[:], secretKeyBytes)

  return secretKey
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

  return secretKey
}

func generateRandomBytes(length int) []byte {
  result := make([]byte, length)
  _, err := rand.Read(result)
  if err != nil {
    panic(err)
  }

  return result
}

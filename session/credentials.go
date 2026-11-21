package session

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Credentials decodes the legacy X-Credentials header and rejects excessive
// input before allocating decoded data. Account logins use the same parser.
func Credentials(header string) (string, []byte, error) {
	if len(header) == 0 || len(header) > 4096 {
		return "", nil, errors.New("Invalid X-Credentials header")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(header)
	if err != nil || len(decoded) > 3072 {
		return "", nil, errors.New("Invalid X-Credentials header")
	}
	fields := strings.SplitN(string(decoded), ":", 2)
	if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
		return "", nil, errors.New("Invalid X-Credentials header value")
	}
	return fields[0], []byte(fields[1]), nil
}

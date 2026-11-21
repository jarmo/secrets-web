package user

import "path/filepath"

func DefaultDirectory(configurationDirectory string) string {
	return filepath.Join(configurationDirectory, "users")
}

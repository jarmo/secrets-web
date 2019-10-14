package xdgdir

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// ConfigDir returns base directory path of config files that does not contain subdirectory for app.
//
// 1. If XDG_CONFIG_HOME envvar is defined, returns it.
// 2. IF HOME envvar is defined, returns $HOME/.config
// 3. IF USERPROFILE envvar is defined, returns $USERPROFILE/.config (for Windows)
func ConfigDir() (string, error) {
	return buildHome("XDG_CONFIG_HOME", ".config")
}

// DataDir returns base directory path of data files that does not contain subdirectory for app.
//
// 1. If XDG_DATA_HOME envvar is defined, returns it.
// 2. IF HOME envvar is defined, returns $HOME/.local/share
// 3. IF USERPROFILE envvar is defined, returns $USERPROFILE/.local/share (for Windows)
func DataDir() (string, error) {
	return buildHome("XDG_DATA_HOME", ".local", "share")
}

// CacheDir returns base directory path of cache files that does not contain subdirectory for app.
//
// 1. If XDG_CACHE_HOME envvar is defined, returns it.
// 2. IF HOME envvar is defined, returns $HOME/.cache
// 3. IF USERPROFILE envvar is defined, returns $USERPROFILE/.cache (for Windows)
func CacheDir() (string, error) {
	return buildHome("XDG_CACHE_HOME", ".cache")
}

// RuntimeDir returns base directory path of runtime files that does not contain subdirectory for app.
//
// 1. If XDG_RUNTIME_DIR envvar is defined, returns it.
// 2. Returns temporary directory path.
func RuntimeDir() string {
	xDir := os.Getenv("XDG_RUNTIME_DIR")
	if xDir != "" {
		return xDir
	}

	return filepath.Join(os.TempDir(), strconv.Itoa(os.Getuid()))
}

func buildHome(env string, paths ...string) (string, error) {
	xdgHome := os.Getenv(env)
	if xdgHome != "" {
		return xdgHome, nil
	}

	home := homeDir()
	if home == "" {
		return "", errors.New("home directory not found")
	}

	elem := make([]string, len(paths)+1)
	elem[0] = home
	for i, p := range paths {
		elem[i+1] = p
	}
	return filepath.Join(elem...), nil
}

func homeDir() string {
	home := os.Getenv("HOME")
	if home != "" {
		return home
	}
	return os.Getenv("USERPROFILE")
}

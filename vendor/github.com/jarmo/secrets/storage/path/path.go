package path

import (
	"encoding/json"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"fmt"
	"io"
	"github.com/juju/fslock"
)

const maxConfigurationSize int64 = 1 << 20

type config struct {
	Path  string
	Alias string
}

type configuration struct {
	UsersDir string `json:",omitempty"`
	Vaults []config
}

// UsersDirectory returns the configured account directory, or an empty string
// when the setting (or configuration file) is absent. Callers supply the
// existing per-application default in that case.
func UsersDirectory(configurationPath string) (string, error) {
	conf, err := loadConfiguration(configurationPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return conf.UsersDir, nil
}

func Get(configurationPath, alias string) (string, error) {
	configs, err := configurations(configurationPath)
	if err != nil {
		return "", err
	}
	if found := findByAlias(configs, alias); found != nil {
		return found.Path, nil
	}
	return "", errors.New("Vault not found!")
}

func Aliases(configurationPath string) ([]string, error) {
  configs, err := configurations(configurationPath)
  if err != nil {
    return nil, err
  }
  aliases := make([]string, 0, len(configs))
  for _, config := range configs {
    aliases = append(aliases, config.Alias)
  }
  return aliases, nil
}

// Store keeps its historical API (panic on an I/O error), but never silently
// replaces a damaged configuration or follows a configuration-file symlink.
func Store(configurationPath, vaultPath, vaultAlias string) string {
	if err := os.MkdirAll(filepath.Dir(configurationPath), 0700); err != nil {
		panic(err)
	}
	absoluteVaultPath, err := filepath.Abs(vaultPath)
	if err != nil {
		panic(err)
	}
	lockPath := configurationPath + ".lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() {
			panic("Configuration lock must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		panic(err)
	}
	locker := fslock.New(lockPath)
	if err := locker.Lock(); err != nil {
		panic(err)
	}
	defer locker.Unlock()

	conf, err := loadConfiguration(configurationPath)
	if err != nil {
		if !os.IsNotExist(err) {
			// Historically an empty, pre-created configuration file was
			// accepted as an uninitialized configuration. Keep that case,
			// but never discard malformed nonempty content.
			info, statErr := os.Lstat(configurationPath)
			if statErr != nil || !info.Mode().IsRegular() || info.Size() != 0 {
				panic(err)
			}
		}
		conf = configuration{}
	}
	conf.Vaults = append(conf.Vaults, config{Path: absoluteVaultPath, Alias: vaultAlias})
	data, err := json.MarshalIndent(conf, "", " ")
	if err != nil {
		panic(err)
	}
	if int64(len(data)) > maxConfigurationSize {
		panic("Vault configuration is too large")
	}
	if err := writeConfiguration(configurationPath, data); err != nil {
		panic(err)
	}
	return configurationPath
}

func configurations(path string) ([]config, error) {
	conf, err := loadConfiguration(path)
	return conf.Vaults, err
}

func loadConfiguration(path string) (configuration, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return configuration{}, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxConfigurationSize {
		return configuration{}, errors.New("Invalid vault configuration file")
	}
	file, err := os.Open(path)
	if err != nil {
		return configuration{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return configuration{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() > maxConfigurationSize {
		return configuration{}, errors.New("Vault configuration file changed or is too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxConfigurationSize+1))
	if err != nil {
		return configuration{}, err
	}
	if int64(len(data)) > maxConfigurationSize {
		return configuration{}, fmt.Errorf("Vault configuration exceeds %d bytes", maxConfigurationSize)
	}
	data = bytes.TrimSpace(data)
	var conf configuration
	if len(data) == 0 {
		return configuration{}, errors.New("Empty vault configuration")
	}
	switch data[0] {
	case '[':
		if err := json.Unmarshal(data, &conf.Vaults); err != nil {
			return configuration{}, err
		}
	case '{':
		if err := json.Unmarshal(data, &conf); err != nil {
			return configuration{}, err
		}
	default:
		return configuration{}, errors.New("Invalid vault configuration format")
	}
	if conf.UsersDir != "" && !filepath.IsAbs(conf.UsersDir) {
		return configuration{}, errors.New("UsersDir must be an absolute path")
	}
	return conf, nil
}

func writeConfiguration(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("Vault configuration must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".secrets-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func findByAlias(configs []config, alias string) *config {
	for _, config := range configs {
		if strings.EqualFold(config.Alias, alias) {
			return &config
		}
	}
	return nil
}

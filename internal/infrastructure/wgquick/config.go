package wgquick

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Service manages wg-quick configuration files.
type Service struct {
	// Searched in order, like wg-quick does.
	configDirs []string
	mu         sync.Mutex
}

// NewService creates a new wg-quick config service.
func NewService(configDirs []string) (*Service, error) {
	if len(configDirs) == 0 {
		return nil, fmt.Errorf("at least one config directory must be specified")
	}
	return &Service{configDirs: configDirs}, nil
}

// path returns the first existing config file for name, or where a new one
// goes: the first directory.
func (s *Service) path(name string) string {
	filename := name + ".conf"
	for _, dir := range s.configDirs {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return filepath.Join(s.configDirs[0], filename)
}

// ListConfigDevices returns names of all devices that have config files.
func (s *Service) ListConfigDevices() []string {
	seen := make(map[string]bool)
	var devices []string

	for _, dir := range s.configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Directory might not exist
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".conf") {
				deviceName := strings.TrimSuffix(name, ".conf")
				if !seen[deviceName] {
					seen[deviceName] = true
					devices = append(devices, deviceName)
				}
			}
		}
	}

	return devices
}

// LoadConfig reads the config file of name.
func (s *Service) LoadConfig(name string) (*Config, error) {
	f, err := os.Open(s.path(name))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ParseConfig(f)
}

// Update applies edit to the config file of name and writes it back
// atomically. A missing file starts empty. A file that exists but cannot be
// read is left alone, since rewriting it would lose its content.
func (s *Service) Update(name string, edit func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.path(name)
	cfg, err := s.LoadConfig(name)
	if errors.Is(err, os.ErrNotExist) {
		cfg, err = ParseConfig(strings.NewReader(""))
	}
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	edit(cfg)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, cfg.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}

	return nil
}

// Up brings up a WireGuard interface using wg-quick.
func (s *Service) Up(name string) error {
	return runWgQuick("up", name)
}

// Down brings down a WireGuard interface using wg-quick.
func (s *Service) Down(name string) error {
	return runWgQuick("down", name)
}

// runWgQuick runs wg-quick, which needs root. It never waits for a sudo
// password: stdin is closed, askpass helpers fail and the call times out.
func runWgQuick(action, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wg-quick", action, name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	devNull, err := os.Open(os.DevNull)
	if err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
	}
	cmd.Env = append(os.Environ(), "SUDO_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false")

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = stdout.String()
		}
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("wg-quick %s timed out (likely waiting for sudo password): run wgrest as root", action)
		}
		if strings.Contains(errMsg, "must be run as root") ||
			strings.Contains(errMsg, "Permission denied") ||
			strings.Contains(errMsg, "Operation not permitted") {
			return fmt.Errorf("wg-quick %s requires root privileges: %s", action, errMsg)
		}
		return fmt.Errorf("wg-quick %s failed: %w: %s", action, err, errMsg)
	}

	return nil
}

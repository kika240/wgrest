package wgquick

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/suquant/wgrest/internal/domain/entity"
	"github.com/suquant/wgrest/internal/infrastructure/wireguard"
)

// Config represents a parsed wg-quick configuration.
type Config struct {
	// Interface section
	PrivateKey   string
	ListenPort   int
	FirewallMark int
	Addresses    []string
	DNS          []string
	MTU          int
	Table        string
	PreUp        []string
	PostUp       []string
	PreDown      []string
	PostDown     []string
	SaveConfig   bool

	// Peers section (raw WireGuard config)
	Peers []PeerConfig
}

// PeerConfig represents a peer in the config file.
type PeerConfig struct {
	PublicKey                   string
	PresharedKey                string
	AllowedIPs                  []string
	Endpoint                    string
	PersistentKeepaliveInterval int
}

// Service manages wg-quick configuration files.
type Service struct {
	// Config directories to search (in order)
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

// ensureDir creates a directory if it doesn't exist.
func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0700)
}

// FindConfigPath searches all directories and returns the first existing config file.
// If not found, returns path in the first directory (for new configs).
func (s *Service) FindConfigPath(name string) string {
	filename := name + ".conf"

	// Search all paths in order
	for _, dir := range s.configDirs {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Not found - return path in first directory (for new configs)
	return filepath.Join(s.configDirs[0], filename)
}

// GetConfigDir returns the directory where a config file exists, or first dir for new configs.
func (s *Service) GetConfigDir(name string) string {
	filename := name + ".conf"

	// Search all paths in order
	for _, dir := range s.configDirs {
		path := filepath.Join(dir, filename)
		if _, err := os.Stat(path); err == nil {
			return dir
		}
	}

	// Not found - return first directory (for new configs)
	return s.configDirs[0]
}

// ConfigDirs returns the configured search directories.
func (s *Service) ConfigDirs() []string {
	return s.configDirs
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

// SaveConfig writes a device configuration to file (in the same directory where found).
func (s *Service) SaveConfig(device *entity.Device, peers []entity.Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Write to the same dir where config was found, or first dir for new configs
	configDir := s.GetConfigDir(device.Name)
	if err := ensureDir(configDir); err != nil {
		return err
	}

	config := s.buildConfig(device, peers)
	configPath := filepath.Join(configDir, device.Name+".conf")
	tmpPath := configPath + ".tmp"

	if err := os.WriteFile(tmpPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}

	return nil
}

// SaveFromShowconf persists the running state of an interface using
// `wg showconf` output.
//
// `wg showconf` only knows about WireGuard's own settings (PrivateKey,
// ListenPort, FwMark and peers). wg-quick settings such as Address, DNS, MTU,
// Table and PreUp/PostUp/PreDown/PostDown are not part of its output, so the
// result is merged into the existing config file instead of replacing it.
// Comments attached to the [Interface] section and to peers are kept too.
func (s *Service) SaveFromShowconf(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// On macOS/BSD the kernel interface is utunX while the config is wg0.conf.
	cmd := exec.Command("wg", "showconf", wireguard.ResolveInterfaceName(name))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg showconf failed: %w: %s", err, stderr.String())
	}

	return s.writeMergedShowconf(name, stdout.Bytes())
}

// writeMergedShowconf merges showconf output into the config file of name and
// writes it atomically. Callers must hold s.mu.
func (s *Service) writeMergedShowconf(name string, showconf []byte) error {
	// Write to the same dir where config was found, or first dir for new configs
	configDir := s.GetConfigDir(name)
	if err := ensureDir(configDir); err != nil {
		return err
	}

	configPath := filepath.Join(configDir, name+".conf")

	content := showconf
	existing, err := os.ReadFile(configPath)
	switch {
	case err == nil:
		content = MergeShowconf(existing, showconf)
	case !os.IsNotExist(err):
		// Never overwrite a config we could not read: it may hold wg-quick
		// settings that showconf output would drop.
		return fmt.Errorf("failed to read existing config: %w", err)
	}

	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}

	return nil
}

// showconfInterfaceKeys are the [Interface] keys that `wg showconf` owns.
var showconfInterfaceKeys = map[string]bool{
	"privatekey": true,
	"listenport": true,
	"fwmark":     true,
}

// configKey returns the lower-cased key of a "Key = Value" line, or "".
func configKey(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	parts := strings.SplitN(trimmed, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func configValue(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func isSection(line, section string) bool {
	return strings.EqualFold(strings.TrimSpace(line), section)
}

func isComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

func splitLines(b []byte) []string {
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// MergeShowconf merges `wg showconf` output into an existing wg-quick config.
//
// From showconf it takes PrivateKey, ListenPort, FwMark and the full list of
// peers (the running state is authoritative). From the existing file it keeps
// everything else in [Interface] (Address, DNS, MTU, Table, hooks, SaveConfig,
// comments, unknown keys) and the comments attached to each peer, matched by
// PublicKey. If the existing file has no [Interface] section, showconf output
// is returned unchanged.
func MergeShowconf(existing, showconf []byte) []byte {
	existingLines := splitLines(existing)
	showLines := splitLines(showconf)

	hasInterface := false
	for _, l := range existingLines {
		if isSection(l, "[Interface]") {
			hasInterface = true
			break
		}
	}
	if !hasInterface {
		return showconf
	}

	// --- showconf: interface keys and peer blocks ---
	showIface := map[string]string{} // key -> full line
	var showIfaceOrder []string
	var showPeers [][]string
	inPeer := false
	for _, l := range showLines {
		switch {
		case isSection(l, "[Interface]"):
			inPeer = false
		case isSection(l, "[Peer]"):
			inPeer = true
			showPeers = append(showPeers, nil)
		case inPeer:
			if strings.TrimSpace(l) != "" {
				showPeers[len(showPeers)-1] = append(showPeers[len(showPeers)-1], l)
			}
		default:
			if k := configKey(l); showconfInterfaceKeys[k] {
				if _, seen := showIface[k]; !seen {
					showIfaceOrder = append(showIfaceOrder, k)
				}
				showIface[k] = l
			}
		}
	}

	// --- existing file: head (up to the first [Peer]) and peer comments ---
	var head []string
	peerComments := map[string][]string{} // public key -> comment lines
	var pending []string                  // comments seen since the last key line
	var curPeerComments []string
	curPeerKey := ""
	flushPeer := func() {
		if curPeerKey != "" && len(curPeerComments) > 0 {
			peerComments[curPeerKey] = append(peerComments[curPeerKey], curPeerComments...)
		}
		curPeerKey, curPeerComments = "", nil
	}
	inPeer = false
	for _, l := range existingLines {
		trimmed := strings.TrimSpace(l)
		switch {
		case isSection(l, "[Peer]"):
			if !inPeer {
				// Comments right above the first [Peer] belong to that peer.
				head = trimTrailingComments(head, len(pending))
			} else {
				flushPeer()
			}
			inPeer = true
			curPeerComments = append(curPeerComments, pending...)
			pending = nil
		case !inPeer:
			head = append(head, l)
			if isComment(l) {
				pending = append(pending, l)
			} else {
				pending = nil
			}
		case isComment(l):
			pending = append(pending, l)
		case trimmed == "":
			// A blank line ends a comment block that sits inside a peer;
			// keep it pending so it can attach to the next [Peer] header.
		default:
			curPeerComments = append(curPeerComments, pending...)
			pending = nil
			if configKey(l) == "publickey" {
				curPeerKey = configValue(l)
			}
		}
	}
	if inPeer {
		curPeerComments = append(curPeerComments, pending...)
		flushPeer()
	}

	// --- rebuild [Interface] ---
	var out []string
	emitted := map[string]bool{}
	inIface := false
	for _, l := range head {
		if isSection(l, "[Interface]") {
			out = append(out, l)
			inIface = true
			// Keys showconf has but the file does not go right after the header.
			for _, k := range showIfaceOrder {
				if !existingHasKey(head, k) {
					out = append(out, showIface[k])
					emitted[k] = true
				}
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			inIface = false
		}
		if k := configKey(l); inIface && showconfInterfaceKeys[k] {
			if line, ok := showIface[k]; ok && !emitted[k] {
				out = append(out, line)
				emitted[k] = true
			}
			// Drop keys showconf no longer reports (e.g. ListenPort removed)
			// and duplicates.
			continue
		}
		out = append(out, l)
	}

	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}

	// --- peers from showconf, with their comments restored ---
	for _, peer := range showPeers {
		out = append(out, "", "[Peer]")
		key := ""
		for _, l := range peer {
			if configKey(l) == "publickey" {
				key = configValue(l)
			}
		}
		out = append(out, peerComments[key]...)
		out = append(out, peer...)
	}

	return []byte(strings.Join(out, "\n") + "\n")
}

// trimTrailingComments drops the last n lines (the comment block right above
// the first [Peer]), along with nothing else.
func trimTrailingComments(lines []string, n int) []string {
	if n > len(lines) {
		n = len(lines)
	}
	return lines[:len(lines)-n]
}

// existingHasKey reports whether the [Interface] section of head has key k.
func existingHasKey(head []string, k string) bool {
	inIface := false
	for _, l := range head {
		if isSection(l, "[Interface]") {
			inIface = true
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			inIface = false
		}
		if inIface && configKey(l) == k {
			return true
		}
	}
	return false
}

// LoadConfig parses a wg-quick config file, searching all paths.
func (s *Service) LoadConfig(name string) (*Config, error) {
	configPath := s.FindConfigPath(name)
	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ParseConfig(f)
}

// Up brings up a WireGuard interface using wg-quick.
// Note: wg-quick typically requires root/sudo.
func (s *Service) Up(name string) error {
	// Use timeout to prevent indefinite waiting for sudo password
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wg-quick", "up", name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Prevent any stdin interaction (sudo password prompts) - use explicit devnull
	devNull, err := os.Open(os.DevNull)
	if err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
	}
	// Set environment to prevent sudo from asking for password
	cmd.Env = append(os.Environ(), "SUDO_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false")

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = stdout.String()
		}
		// Check for context timeout (usually means waiting for sudo)
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("wg-quick up timed out (likely waiting for sudo password): run wgrest as root")
		}
		// Check for permission errors
		if strings.Contains(errMsg, "must be run as root") ||
			strings.Contains(errMsg, "Permission denied") ||
			strings.Contains(errMsg, "Operation not permitted") {
			return fmt.Errorf("wg-quick up requires root privileges: %s", errMsg)
		}
		return fmt.Errorf("wg-quick up failed: %w: %s", err, errMsg)
	}

	return nil
}

// Down brings down a WireGuard interface using wg-quick.
// Note: wg-quick typically requires root/sudo.
func (s *Service) Down(name string) error {
	// Use timeout to prevent indefinite waiting for sudo password
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wg-quick", "down", name)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Prevent any stdin interaction (sudo password prompts) - use explicit devnull
	devNull, err := os.Open(os.DevNull)
	if err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
	}
	// Set environment to prevent sudo from asking for password
	cmd.Env = append(os.Environ(), "SUDO_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false")

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = stdout.String()
		}
		// Check for context timeout (usually means waiting for sudo)
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("wg-quick down timed out (likely waiting for sudo password): run wgrest as root")
		}
		// Check for permission errors
		if strings.Contains(errMsg, "must be run as root") ||
			strings.Contains(errMsg, "Permission denied") ||
			strings.Contains(errMsg, "Operation not permitted") {
			return fmt.Errorf("wg-quick down requires root privileges: %s", errMsg)
		}
		return fmt.Errorf("wg-quick down failed: %w: %s", err, errMsg)
	}

	return nil
}

// GetPlatform returns the current platform (linux, darwin, freebsd).
func GetPlatform() string {
	return runtime.GOOS
}

func (s *Service) buildConfig(device *entity.Device, peers []entity.Peer) string {
	var b strings.Builder

	b.WriteString("[Interface]\n")

	if device.PrivateKey != "" {
		b.WriteString(fmt.Sprintf("PrivateKey = %s\n", device.PrivateKey))
	}

	if device.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", device.ListenPort))
	}

	if device.FirewallMark > 0 {
		b.WriteString(fmt.Sprintf("FwMark = %d\n", device.FirewallMark))
	}

	for _, addr := range device.Addresses {
		b.WriteString(fmt.Sprintf("Address = %s\n", addr))
	}

	if len(device.DNS) > 0 {
		b.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(device.DNS, ", ")))
	}

	if device.MTU > 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", device.MTU))
	}

	if device.Table != "" {
		b.WriteString(fmt.Sprintf("Table = %s\n", device.Table))
	}

	for _, cmd := range device.PreUp {
		b.WriteString(fmt.Sprintf("PreUp = %s\n", cmd))
	}

	for _, cmd := range device.PostUp {
		b.WriteString(fmt.Sprintf("PostUp = %s\n", cmd))
	}

	for _, cmd := range device.PreDown {
		b.WriteString(fmt.Sprintf("PreDown = %s\n", cmd))
	}

	for _, cmd := range device.PostDown {
		b.WriteString(fmt.Sprintf("PostDown = %s\n", cmd))
	}

	// Add peers
	for _, peer := range peers {
		b.WriteString("\n[Peer]\n")
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))

		if peer.PresharedKey != "" {
			b.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey))
		}

		if len(peer.AllowedIPs) > 0 {
			b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", ")))
		}

		if peer.Endpoint != "" {
			b.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}

		if secs := keepaliveSeconds(peer.PersistentKeepaliveInterval); secs > 0 {
			b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", secs))
		}
	}

	return b.String()
}

// keepaliveSeconds converts the API keepalive value ("25s", "1m" or a bare
// number of seconds) to the integer seconds that wg-quick expects.
func keepaliveSeconds(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil {
		return int(d / time.Second)
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
		return n
	}
	return 0
}

// ParseConfig parses a wg-quick configuration file.
func ParseConfig(r io.Reader) (*Config, error) {
	cfg := &Config{}
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section headers
		if line == "[Interface]" {
			currentPeer = nil
			continue
		}
		if line == "[Peer]" {
			currentPeer = &PeerConfig{}
			cfg.Peers = append(cfg.Peers, *currentPeer)
			continue
		}

		// Key-value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		if currentPeer != nil {
			// Peer section
			switch key {
			case "publickey":
				cfg.Peers[len(cfg.Peers)-1].PublicKey = value
			case "presharedkey":
				cfg.Peers[len(cfg.Peers)-1].PresharedKey = value
			case "allowedips":
				ips := strings.Split(value, ",")
				for _, ip := range ips {
					cfg.Peers[len(cfg.Peers)-1].AllowedIPs = append(cfg.Peers[len(cfg.Peers)-1].AllowedIPs, strings.TrimSpace(ip))
				}
			case "endpoint":
				cfg.Peers[len(cfg.Peers)-1].Endpoint = value
			case "persistentkeepalive":
				fmt.Sscanf(value, "%d", &cfg.Peers[len(cfg.Peers)-1].PersistentKeepaliveInterval)
			}
		} else {
			// Interface section
			switch key {
			case "privatekey":
				cfg.PrivateKey = value
			case "listenport":
				fmt.Sscanf(value, "%d", &cfg.ListenPort)
			case "fwmark":
				fmt.Sscanf(value, "%d", &cfg.FirewallMark)
			case "address":
				addrs := strings.Split(value, ",")
				for _, addr := range addrs {
					cfg.Addresses = append(cfg.Addresses, strings.TrimSpace(addr))
				}
			case "dns":
				servers := strings.Split(value, ",")
				for _, s := range servers {
					cfg.DNS = append(cfg.DNS, strings.TrimSpace(s))
				}
			case "mtu":
				fmt.Sscanf(value, "%d", &cfg.MTU)
			case "table":
				cfg.Table = value
			case "preup":
				cfg.PreUp = append(cfg.PreUp, value)
			case "postup":
				cfg.PostUp = append(cfg.PostUp, value)
			case "predown":
				cfg.PreDown = append(cfg.PreDown, value)
			case "postdown":
				cfg.PostDown = append(cfg.PostDown, value)
			case "saveconfig":
				cfg.SaveConfig = strings.ToLower(value) == "true"
			}
		}
	}

	return cfg, scanner.Err()
}

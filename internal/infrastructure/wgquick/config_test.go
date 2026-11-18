package wgquick

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/suquant/wgrest/internal/domain/entity"
)

// serverConfig is a hand-written wg-quick file with everything a dump must
// not lose: wg-quick-only keys, keys wgrest does not know, comments, hex
// numbers and a peer named by a comment.
const serverConfig = `# Managed by hand
[Interface]
# Server side
Address = 10.0.0.1/24, fd00::1/64
PrivateKey = OLDKEY=
ListenPort = 51000
FwMark = 0x10
DNS = 1.1.1.1
MTU = 1420
Table = off
SaveConfig = false
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Alice laptop
[Peer]
PublicKey = ALICE=
AllowedIPs = 10.0.0.2/32

# Bob phone
[Peer]
PublicKey = BOB=
AllowedIPs = 10.0.0.3/32
`

func parse(t *testing.T, s string) *Config {
	t.Helper()
	cfg, err := ParseConfig(strings.NewReader(s))
	require.NoError(t, err)
	return cfg
}

func TestConfig_RoundTripKeepsFileAsWritten(t *testing.T) {
	assert.Equal(t, serverConfig, string(parse(t, serverConfig).Bytes()))
}

func TestConfig_Options(t *testing.T) {
	cfg := parse(t, `[interface]
address = 10.0.0.1/24
Address = fd00::1/64
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420
Table = auto
PreUp = echo "pre-up"
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = ip6tables -A FORWARD -i wg0 -j ACCEPT
PreDown = echo "pre-down"
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
`)

	assert.Equal(t, entity.QuickOptions{
		Addresses: []string{"10.0.0.1/24", "fd00::1/64"},
		DNS:       []string{"1.1.1.1", "8.8.8.8"},
		MTU:       1420,
		Table:     "auto",
		PreUp:     []string{`echo "pre-up"`},
		PostUp:    []string{"iptables -A FORWARD -i wg0 -j ACCEPT", "ip6tables -A FORWARD -i wg0 -j ACCEPT"},
		PreDown:   []string{`echo "pre-down"`},
		PostDown:  []string{"iptables -D FORWARD -i wg0 -j ACCEPT"},
	}, cfg.Options())
}

func TestConfig_DeviceOfStoppedInterface(t *testing.T) {
	d := parse(t, serverConfig).Device("wg0")

	assert.Equal(t, "wg0", d.Name)
	assert.Equal(t, "OLDKEY=", d.PrivateKey)
	assert.Equal(t, int32(51000), d.ListenPort)
	assert.Equal(t, int32(16), d.FirewallMark)
	assert.Equal(t, []string{"10.0.0.1/24", "fd00::1/64"}, d.Addresses)
	assert.False(t, d.Running)
}

func running() (*entity.Device, []entity.Peer) {
	device := &entity.Device{PrivateKey: "NEWKEY=", ListenPort: 51820, FirewallMark: 16}
	peers := []entity.Peer{
		{PublicKey: "ALICE=", AllowedIPs: []string{"10.0.0.2/32"}, Endpoint: "203.0.113.5:40000", PersistentKeepaliveInterval: "25s"},
		{PublicKey: "CAROL=", AllowedIPs: []string{"10.0.0.4/32", "fd00::4/128"}, PersistentKeepaliveInterval: "0s"},
	}
	return device, peers
}

// The regression this package exists to prevent: saving the running state
// must not wipe Address, DNS, hooks and the rest of the hand-written file.
func TestConfig_SetRunningKeepsEverythingTheKernelDoesNotKnow(t *testing.T) {
	cfg := parse(t, serverConfig)
	cfg.SetRunning(running())

	assert.Equal(t, `# Managed by hand
[Interface]
# Server side
Address = 10.0.0.1/24, fd00::1/64
PrivateKey = NEWKEY=
ListenPort = 51820
FwMark = 0x10
DNS = 1.1.1.1
MTU = 1420
Table = off
SaveConfig = false
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Alice laptop
[Peer]
PublicKey = ALICE=
AllowedIPs = 10.0.0.2/32
Endpoint = 203.0.113.5:40000
PersistentKeepalive = 25

[Peer]
PublicKey = CAROL=
AllowedIPs = 10.0.0.4/32, fd00::4/128
`, string(cfg.Bytes()))
}

func TestConfig_SetRunningIsStable(t *testing.T) {
	cfg := parse(t, serverConfig)
	cfg.SetRunning(running())
	once := string(cfg.Bytes())

	again := parse(t, once)
	again.SetRunning(running())
	assert.Equal(t, once, string(again.Bytes()))
}

func TestConfig_SetRunningOnEmptyFile(t *testing.T) {
	cfg := parse(t, "")
	cfg.SetRunning(running())

	reread := parse(t, string(cfg.Bytes())).Device("wg0")
	assert.Equal(t, "NEWKEY=", reread.PrivateKey)
	assert.Equal(t, int32(51820), reread.ListenPort)
	assert.Contains(t, string(cfg.Bytes()), "[Peer]\nPublicKey = CAROL=\n")
}

// A PATCH on the device used to rebuild the file from scratch.
func TestConfig_SetOptionsKeepsKernelKeysCommentsAndUnknownKeys(t *testing.T) {
	cfg := parse(t, serverConfig)
	opts := cfg.Options()
	opts.DNS = []string{"9.9.9.9"}
	opts.PostUp = nil
	opts.PostDown = nil
	cfg.SetOptions(opts)

	out := string(cfg.Bytes())
	assert.Contains(t, out, "# Managed by hand\n[Interface]\n# Server side\n")
	assert.Contains(t, out, "PrivateKey = OLDKEY=\nListenPort = 51000\nFwMark = 0x10\nDNS = 9.9.9.9\n")
	assert.Contains(t, out, "SaveConfig = false\n")
	assert.NotContains(t, out, "PostUp")
	assert.NotContains(t, out, "PostDown")
	assert.Contains(t, out, "# Bob phone\n[Peer]\nPublicKey = BOB=\n")
	assert.Equal(t, opts, parse(t, out).Options())
}

func TestService_UpdateKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	require.NoError(t, os.WriteFile(path, []byte(serverConfig), 0600))
	svc, err := NewService([]string{t.TempDir(), dir})
	require.NoError(t, err)

	require.NoError(t, svc.Update("wg0", func(c *Config) error { c.SetRunning(running()); return nil }))

	cfg, err := svc.LoadConfig("wg0")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1/24", "fd00::1/64"}, cfg.Options().Addresses)
	assert.Equal(t, "NEWKEY=", cfg.Device("wg0").PrivateKey)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestService_UpdateCreatesFileInFirstDir(t *testing.T) {
	first := filepath.Join(t.TempDir(), "missing")
	svc, err := NewService([]string{first, t.TempDir()})
	require.NoError(t, err)

	require.NoError(t, svc.Update("wg1", func(c *Config) error { c.SetRunning(running()); return nil }))

	_, err = os.Stat(filepath.Join(first, "wg1.conf"))
	assert.NoError(t, err)
}

func TestService_UpdateLeavesUnreadableFileAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	unreadable := "[Interface]\nPostUp = " + strings.Repeat("x", 128*1024) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(unreadable), 0600))
	svc, err := NewService([]string{dir})
	require.NoError(t, err)

	err = svc.Update("wg0", func(c *Config) error { c.SetRunning(running()); return nil })
	assert.Error(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, unreadable, string(data))
}

func TestService_UpdateWritesNothingWhenEditFails(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService([]string{dir})
	require.NoError(t, err)

	err = svc.Update("wg0", func(c *Config) error { return os.ErrPermission })
	assert.ErrorIs(t, err, os.ErrPermission)

	_, err = os.Stat(filepath.Join(dir, "wg0.conf"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// wg-quick ignores everything after a "#", so inline comments must neither
// hide a peer nor end up in a value.
func TestConfig_InlineComments(t *testing.T) {
	file := `[Interface]
Address = 10.0.0.1/24 # main
PrivateKey = K=

# Alice
[Peer]
PublicKey = ALICE= # phone
AllowedIPs = 10.0.0.2/32 # phone
PersistentKeepalive = 25

# end of file
`
	cfg := parse(t, file)
	assert.Equal(t, []string{"10.0.0.1/24"}, cfg.Options().Addresses)

	cfg.SetRunning(&entity.Device{PrivateKey: "K="}, []entity.Peer{
		{PublicKey: "ALICE=", AllowedIPs: []string{"10.0.0.2/32"}, PersistentKeepaliveInterval: "25s"},
	})
	assert.Equal(t, file, string(cfg.Bytes()))
}

func TestConfig_RemovingLastPeerKeepsEndOfFileComment(t *testing.T) {
	cfg := parse(t, serverConfig+"\n# end of file\n")
	cfg.SetRunning(&entity.Device{PrivateKey: "OLDKEY=", ListenPort: 51000, FirewallMark: 16}, []entity.Peer{
		{PublicKey: "ALICE=", AllowedIPs: []string{"10.0.0.2/32"}},
	})

	out := string(cfg.Bytes())
	assert.NotContains(t, out, "BOB=")
	assert.NotContains(t, out, "# Bob phone")
	assert.True(t, strings.HasSuffix(out, "AllowedIPs = 10.0.0.2/32\n\n# end of file\n"), out)
}

func TestListConfigDevices(t *testing.T) {
	// Create temp dir with config files
	tmpDir := t.TempDir()
	err := os.WriteFile(tmpDir+"/wg0.conf", []byte("[Interface]\n"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(tmpDir+"/wg1.conf", []byte("[Interface]\n"), 0600)
	require.NoError(t, err)
	// Create a non-config file (should be ignored)
	err = os.WriteFile(tmpDir+"/readme.txt", []byte("test"), 0600)
	require.NoError(t, err)

	svc := &Service{configDirs: []string{tmpDir}}
	devices := svc.ListConfigDevices()

	assert.Len(t, devices, 2)
	assert.Contains(t, devices, "wg0")
	assert.Contains(t, devices, "wg1")
}

func TestListConfigDevices_MultipleDirs(t *testing.T) {
	// Create two temp dirs with config files
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	err := os.WriteFile(tmpDir1+"/wg0.conf", []byte("[Interface]\n"), 0600)
	require.NoError(t, err)
	err = os.WriteFile(tmpDir2+"/wg1.conf", []byte("[Interface]\n"), 0600)
	require.NoError(t, err)
	// Same device in both dirs (should be deduplicated)
	err = os.WriteFile(tmpDir2+"/wg0.conf", []byte("[Interface]\n"), 0600)
	require.NoError(t, err)

	svc := &Service{configDirs: []string{tmpDir1, tmpDir2}}
	devices := svc.ListConfigDevices()

	// Should have 2 unique devices, not 3
	assert.Len(t, devices, 2)
	assert.Contains(t, devices, "wg0")
	assert.Contains(t, devices, "wg1")
}

func TestNewService_EmptyDirs(t *testing.T) {
	_, err := NewService([]string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one config directory")
}

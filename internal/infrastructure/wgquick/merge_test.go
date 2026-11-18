package wgquick

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const showconfOutput = `[Interface]
ListenPort = 51820
PrivateKey = NEWPRIVATEKEY=

[Peer]
PublicKey = PEER1=
AllowedIPs = 10.0.0.2/32
Endpoint = 203.0.113.5:40000

[Peer]
PublicKey = PEER3=
AllowedIPs = 10.0.0.4/32
`

const existingConfig = `# Managed by wgrest
[Interface]
# Server side
Address = 10.0.0.1/24
PrivateKey = OLDPRIVATEKEY=
ListenPort = 51000
DNS = 1.1.1.1
MTU = 1420
Table = off
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Alice laptop
[Peer]
PublicKey = PEER1=
AllowedIPs = 10.0.0.2/32

[Peer]
# Bob phone (removed at runtime)
PublicKey = PEER2=
AllowedIPs = 10.0.0.3/32
`

func TestMergeShowconf_KeepsWgQuickSettings(t *testing.T) {
	out := string(MergeShowconf([]byte(existingConfig), []byte(showconfOutput)))

	cfg, err := ParseConfig(strings.NewReader(out))
	require.NoError(t, err)

	// wg-quick-only settings survive the dump.
	assert.Equal(t, []string{"10.0.0.1/24"}, cfg.Addresses)
	assert.Equal(t, []string{"1.1.1.1"}, cfg.DNS)
	assert.Equal(t, 1420, cfg.MTU)
	assert.Equal(t, "off", cfg.Table)
	assert.Equal(t, []string{"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"}, cfg.PostUp)
	assert.Equal(t, []string{"iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"}, cfg.PostDown)

	// Runtime state wins for WireGuard settings and peers.
	assert.Equal(t, "NEWPRIVATEKEY=", cfg.PrivateKey)
	assert.Equal(t, 51820, cfg.ListenPort)
	require.Len(t, cfg.Peers, 2)
	assert.Equal(t, "PEER1=", cfg.Peers[0].PublicKey)
	assert.Equal(t, "203.0.113.5:40000", cfg.Peers[0].Endpoint)
	assert.Equal(t, "PEER3=", cfg.Peers[1].PublicKey)
	assert.NotContains(t, out, "PEER2=")
	assert.NotContains(t, out, "OLDPRIVATEKEY=")
	assert.NotContains(t, out, "51000")

	// Comments are kept: file header, interface, and the surviving peer's.
	assert.Contains(t, out, "# Managed by wgrest\n[Interface]\n# Server side\n")
	assert.Contains(t, out, "[Peer]\n# Alice laptop\nPublicKey = PEER1=\n")
	assert.NotContains(t, out, "Bob phone")
}

func TestMergeShowconf_KeyOrderPreserved(t *testing.T) {
	out := string(MergeShowconf([]byte(existingConfig), []byte(showconfOutput)))
	assert.Contains(t, out, "Address = 10.0.0.1/24\nPrivateKey = NEWPRIVATEKEY=\nListenPort = 51820\nDNS = 1.1.1.1\n")
}

func TestMergeShowconf_AddsAndDropsWireGuardKeys(t *testing.T) {
	existing := "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = K=\nListenPort = 51000\n"
	showconf := "[Interface]\nPrivateKey = K=\nFwMark = 0x1\n"

	out := string(MergeShowconf([]byte(existing), []byte(showconf)))

	assert.Equal(t, "[Interface]\nFwMark = 0x1\nAddress = 10.0.0.1/24\nPrivateKey = K=\n", out)
}

func TestMergeShowconf_NoInterfaceSection(t *testing.T) {
	out := MergeShowconf([]byte("# empty\n"), []byte(showconfOutput))
	assert.Equal(t, showconfOutput, string(out))
}

func TestMergeShowconf_Idempotent(t *testing.T) {
	once := MergeShowconf([]byte(existingConfig), []byte(showconfOutput))
	twice := MergeShowconf(once, []byte(showconfOutput))
	assert.Equal(t, string(once), string(twice))
}

func TestWriteMergedShowconf(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService([]string{dir})
	require.NoError(t, err)

	path := filepath.Join(dir, "wg0.conf")
	require.NoError(t, os.WriteFile(path, []byte(existingConfig), 0600))

	require.NoError(t, svc.writeMergedShowconf("wg0", []byte(showconfOutput)))

	cfg, err := svc.LoadConfig("wg0")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1/24"}, cfg.Addresses)
	assert.Len(t, cfg.Peers, 2)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestWriteMergedShowconf_NewFile(t *testing.T) {
	dir := t.TempDir()
	svc, err := NewService([]string{dir})
	require.NoError(t, err)

	require.NoError(t, svc.writeMergedShowconf("wg1", []byte(showconfOutput)))

	data, err := os.ReadFile(filepath.Join(dir, "wg1.conf"))
	require.NoError(t, err)
	assert.Equal(t, showconfOutput, string(data))
}

func TestKeepaliveSeconds(t *testing.T) {
	assert.Equal(t, 25, keepaliveSeconds("25s"))
	assert.Equal(t, 60, keepaliveSeconds("1m"))
	assert.Equal(t, 15, keepaliveSeconds("15"))
	assert.Equal(t, 0, keepaliveSeconds("0s"))
	assert.Equal(t, 0, keepaliveSeconds(""))
}

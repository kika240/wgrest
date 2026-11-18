package wireguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// record writes what wg-quick on macOS leaves in its run dir for an interface.
func record(t *testing.T, dir, logical, real string, sockAge time.Duration) {
	t.Helper()
	now := time.Now()
	nameFile := filepath.Join(dir, logical+".name")
	sockFile := filepath.Join(dir, real+".sock")
	require.NoError(t, os.WriteFile(nameFile, []byte(real+"\n"), 0600))
	require.NoError(t, os.WriteFile(sockFile, nil, 0600))
	require.NoError(t, os.Chtimes(nameFile, now, now))
	require.NoError(t, os.Chtimes(sockFile, now.Add(-sockAge), now.Add(-sockAge)))
}

func TestInterfaceNames(t *testing.T) {
	dir := t.TempDir()
	record(t, dir, "wg0", "utun7", 0)
	c := &Client{runDir: dir}

	assert.Equal(t, "utun7", c.realName("wg0"))
	assert.Equal(t, "wg0", c.logicalName("utun7"))

	assert.Equal(t, "wg1", c.realName("wg1"))
	assert.Equal(t, "utun3", c.logicalName("utun3"))
}

func TestInterfaceNames_NoRunDir(t *testing.T) {
	c := &Client{runDir: filepath.Join(t.TempDir(), "missing")}

	assert.Equal(t, "wg0", c.realName("wg0"))
	assert.Equal(t, "wg0", c.logicalName("wg0"))
}

// A record left by a crashed wireguard-go must not name another interface
// that later got the same utunX, or the dump would write it into wg0.conf.
func TestInterfaceNames_IgnoresStaleRecord(t *testing.T) {
	dir := t.TempDir()
	record(t, dir, "wg0", "utun3", time.Minute)
	c := &Client{runDir: dir}

	assert.Equal(t, "wg0", c.realName("wg0"))
	assert.Equal(t, "utun3", c.logicalName("utun3"))

	require.NoError(t, os.Remove(filepath.Join(dir, "utun3.sock")))
	record(t, dir, "wg1", "utun4", 0)
	require.NoError(t, os.Remove(filepath.Join(dir, "utun4.sock")))
	assert.Equal(t, "wg1", c.realName("wg1"))
}

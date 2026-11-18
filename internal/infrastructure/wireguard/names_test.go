package wireguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaceNames(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wg0.name"), []byte("utun7\n"), 0600))
	c := &Client{runDir: dir}

	assert.Equal(t, "utun7", c.realName("wg0"))
	assert.Equal(t, "wg0", c.logicalName("utun7"))

	assert.Equal(t, "wg1", c.realName("wg1"))
	assert.Equal(t, "utun3", c.logicalName("utun3"))

	linux := &Client{runDir: filepath.Join(dir, "missing")}
	assert.Equal(t, "wg0", linux.realName("wg0"))
	assert.Equal(t, "wg0", linux.logicalName("wg0"))
}

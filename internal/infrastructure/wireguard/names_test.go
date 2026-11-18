package wireguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaceNameMapping(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wg0.name"), []byte("utun7\n"), 0600))

	assert.Equal(t, "utun7", resolveInterfaceNameIn(dir, "wg0"))
	assert.Equal(t, "wg1", resolveInterfaceNameIn(dir, "wg1"))

	assert.Equal(t, "wg0", logicalInterfaceNameIn(dir, "utun7"))
	assert.Equal(t, "utun3", logicalInterfaceNameIn(dir, "utun3"))
	assert.Equal(t, "utun7", logicalInterfaceNameIn(filepath.Join(dir, "missing"), "utun7"))
}

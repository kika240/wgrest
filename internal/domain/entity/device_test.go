package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyOptions(t *testing.T) {
	opts := QuickOptions{
		Addresses: []string{"10.0.0.1/24"},
		DNS:       []string{"1.1.1.1"},
		MTU:       1420,
		PostUp:    []string{"iptables -A FORWARD -i wg0 -j ACCEPT"},
	}
	mtu := int32(1380)

	DeviceCreateOrUpdateRequest{
		DNS:    []string{"9.9.9.9"},
		MTU:    &mtu,
		PostUp: []string{}, // explicit empty list clears
	}.ApplyOptions(&opts)

	assert.Equal(t, QuickOptions{
		Addresses: []string{"10.0.0.1/24"}, // left out: kept
		DNS:       []string{"9.9.9.9"},
		MTU:       1380,
		PostUp:    []string{},
	}, opts)
}

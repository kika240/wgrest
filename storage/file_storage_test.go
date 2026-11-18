package storage

import (
	"os"
	"path"
	"reflect"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestFileStorageDeviceOptionsRoundTrip(t *testing.T) {
	s, err := NewFileStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	in := StoreDeviceOptions{
		DNSServers: []string{"8.8.8.8", "1.1.1.1"},
		AllowedIPs: []string{"0.0.0.0/0", "::0/0"},
		Host:       "vpn.example.com",
	}
	if err := s.WriteDeviceOptions("wg0", in); err != nil {
		t.Fatal(err)
	}

	out, err := s.ReadDeviceOptions("wg0")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*out, in) {
		t.Fatalf("got %+v, want %+v", *out, in)
	}

	info, err := os.Stat(path.Join(s.(*FileStorage).dir, "wg0.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("got file mode %o, want 600", perm)
	}
}

func TestFileStoragePeerOptionsRoundTrip(t *testing.T) {
	s, err := NewFileStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	in := StorePeerOptions{PrivateKey: key.String()}
	if err := s.WritePeerOptions(key.PublicKey(), in); err != nil {
		t.Fatal(err)
	}

	out, err := s.ReadPeerOptions(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if out.PrivateKey != in.PrivateKey {
		t.Fatalf("got %q, want %q", out.PrivateKey, in.PrivateKey)
	}
}

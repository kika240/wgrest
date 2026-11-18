package wireguard

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/suquant/wgrest/internal/domain/entity"
)

// EmptyKey represents an empty WireGuard key (all zeros).
var EmptyKey = wgtypes.Key{}

// Client provides access to WireGuard devices via wgctrl.
type Client struct {
	ctrl *wgctrl.Client
	// runDir is where wg-quick on macOS/BSD records which utunX interface
	// backs a logical name such as wg0 (wg0.name contains "utun7").
	runDir string
}

// NewClient creates a new WireGuard client.
func NewClient() (*Client, error) {
	ctrl, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	return &Client{ctrl: ctrl, runDir: "/var/run/wireguard"}, nil
}

// Close closes the WireGuard client.
func (c *Client) Close() error {
	return c.ctrl.Close()
}

// realName returns the kernel interface behind a logical name.
func (c *Client) realName(name string) string {
	data, err := os.ReadFile(filepath.Join(c.runDir, name+".name"))
	if err != nil {
		return name
	}
	if real := strings.TrimSpace(string(data)); real != "" {
		return real
	}
	return name
}

// logicalName is the inverse of realName.
func (c *Client) logicalName(real string) string {
	entries, err := os.ReadDir(c.runDir)
	if err != nil {
		return real
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".name") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.runDir, e.Name()))
		if err == nil && strings.TrimSpace(string(data)) == real {
			return strings.TrimSuffix(e.Name(), ".name")
		}
	}
	return real
}

// device reads a device by its logical name.
func (c *Client) device(name string) (*wgtypes.Device, error) {
	d, err := c.ctrl.Device(c.realName(name))
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "does not exist") ||
			strings.Contains(err.Error(), "no such file") ||
			strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("device %s not found", name)
		}
		return nil, fmt.Errorf("failed to get device %s: %w", name, err)
	}
	return d, nil
}

// configure configures a device by its logical name.
func (c *Client) configure(name string, cfg wgtypes.Config) error {
	return c.ctrl.ConfigureDevice(c.realName(name), cfg)
}

// toEntity converts a device, naming it by its logical name.
func (c *Client) toEntity(d *wgtypes.Device) entity.Device {
	device := deviceToEntity(d)
	device.Name = c.logicalName(d.Name)
	return device
}

// List returns all WireGuard devices.
func (c *Client) List() ([]entity.Device, error) {
	devices, err := c.ctrl.Devices()
	if err != nil {
		return nil, err
	}

	result := make([]entity.Device, len(devices))
	for i, d := range devices {
		result[i] = c.toEntity(d)
	}

	return result, nil
}

// Get returns a specific device by name.
func (c *Client) Get(name string) (*entity.Device, error) {
	d, err := c.device(name)
	if err != nil {
		return nil, err
	}

	device := c.toEntity(d)
	return &device, nil
}

// Create creates a new WireGuard device.
func (c *Client) Create(req entity.DeviceCreateOrUpdateRequest) (*entity.Device, error) {
	if req.Name == nil || *req.Name == "" {
		return nil, fmt.Errorf("device name is required")
	}

	name := *req.Name

	_, err := c.device(name)
	if err == nil {
		return nil, fmt.Errorf("device %s already exists", name)
	}

	cfg := wgtypes.Config{}

	if req.PrivateKey != nil {
		key, err := wgtypes.ParseKey(*req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		cfg.PrivateKey = &key
	}

	if req.ListenPort != nil {
		port := int(*req.ListenPort)
		cfg.ListenPort = &port
	}

	if req.FirewallMark != nil {
		mark := int(*req.FirewallMark)
		cfg.FirewallMark = &mark
	}

	if err := c.configure(name, cfg); err != nil {
		return nil, err
	}

	return c.Get(name)
}

// Update updates an existing WireGuard device.
func (c *Client) Update(name string, req entity.DeviceCreateOrUpdateRequest) (*entity.Device, error) {
	if _, err := c.device(name); err != nil {
		return nil, err
	}

	cfg := wgtypes.Config{}

	if req.PrivateKey != nil {
		key, err := wgtypes.ParseKey(*req.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		cfg.PrivateKey = &key
	}

	if req.ListenPort != nil {
		port := int(*req.ListenPort)
		cfg.ListenPort = &port
	}

	if req.FirewallMark != nil {
		mark := int(*req.FirewallMark)
		cfg.FirewallMark = &mark
	}

	if err := c.configure(name, cfg); err != nil {
		return nil, err
	}

	return c.Get(name)
}

// Delete removes a WireGuard device.
func (c *Client) Delete(name string) error {
	// Note: wgctrl doesn't support device deletion directly
	// This would typically be handled by removing the network interface
	return fmt.Errorf("device deletion not supported via wgctrl")
}

// ListPeers returns all peers for a device.
func (c *Client) ListPeers(deviceName string) ([]entity.Peer, error) {
	d, err := c.device(deviceName)
	if err != nil {
		return nil, err
	}

	result := make([]entity.Peer, len(d.Peers))
	for i, p := range d.Peers {
		result[i] = peerToEntity(p)
	}

	return result, nil
}

// GetPeer returns a specific peer by URL-safe public key.
func (c *Client) GetPeer(deviceName string, urlSafePubKey string) (*entity.Peer, error) {
	pubKey, err := decodeURLSafeKey(urlSafePubKey)
	if err != nil {
		return nil, err
	}

	d, err := c.device(deviceName)
	if err != nil {
		return nil, err
	}

	for _, p := range d.Peers {
		if p.PublicKey.String() == pubKey.String() {
			peer := peerToEntity(p)
			return &peer, nil
		}
	}

	return nil, fmt.Errorf("peer not found")
}

// CreatePeer creates a new peer for a device.
func (c *Client) CreatePeer(deviceName string, req entity.PeerCreateOrUpdateRequest) (*entity.Peer, error) {
	d, err := c.device(deviceName)
	if err != nil {
		return nil, err
	}

	peerCfg := wgtypes.PeerConfig{}

	// Generate or use provided keys
	if req.PublicKey != nil {
		key, err := wgtypes.ParseKey(*req.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
		peerCfg.PublicKey = key
	} else {
		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		peerCfg.PublicKey = privateKey.PublicKey()
		// Store private key in request for caller to persist
		pk := privateKey.String()
		req.PrivateKey = &pk
	}

	if req.PresharedKey != nil {
		key, err := wgtypes.ParseKey(*req.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid preshared key: %w", err)
		}
		peerCfg.PresharedKey = &key
	}

	if len(req.AllowedIPs) > 0 {
		allowedIPs := make([]net.IPNet, 0, len(req.AllowedIPs))
		for _, ip := range req.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid allowed IP %s: %w", ip, err)
			}
			allowedIPs = append(allowedIPs, *ipNet)
		}
		peerCfg.AllowedIPs = allowedIPs
	}

	if req.PersistentKeepaliveInterval != nil {
		duration, err := time.ParseDuration(*req.PersistentKeepaliveInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid keepalive interval: %w", err)
		}
		peerCfg.PersistentKeepaliveInterval = &duration
	}

	if req.Endpoint != nil && *req.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", *req.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint: %w", err)
		}
		peerCfg.Endpoint = addr
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := c.ctrl.ConfigureDevice(d.Name, cfg); err != nil {
		return nil, err
	}

	peer := entity.Peer{
		PublicKey:                   peerCfg.PublicKey.String(),
		URLSafePublicKey:            base64.URLEncoding.EncodeToString(peerCfg.PublicKey[:]),
		AllowedIPs:                  req.AllowedIPs,
		PersistentKeepaliveInterval: "0s",
		LastHandshakeTime:           time.Time{},
	}

	if req.PrivateKey != nil {
		peer.PrivateKey = *req.PrivateKey
	}

	if req.PresharedKey != nil {
		peer.PresharedKey = *req.PresharedKey
	}

	if req.PersistentKeepaliveInterval != nil {
		peer.PersistentKeepaliveInterval = *req.PersistentKeepaliveInterval
	}

	if req.Endpoint != nil {
		peer.Endpoint = *req.Endpoint
	}

	return &peer, nil
}

// UpdatePeer updates an existing peer.
func (c *Client) UpdatePeer(deviceName string, urlSafePubKey string, req entity.PeerCreateOrUpdateRequest) (*entity.Peer, error) {
	pubKey, err := decodeURLSafeKey(urlSafePubKey)
	if err != nil {
		return nil, err
	}

	d, err := c.device(deviceName)
	if err != nil {
		return nil, err
	}

	var existingPeer *wgtypes.Peer
	for _, p := range d.Peers {
		if p.PublicKey.String() == pubKey.String() {
			existingPeer = &p
			break
		}
	}

	if existingPeer == nil {
		return nil, fmt.Errorf("peer not found")
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         *pubKey,
		UpdateOnly:        true,
		ReplaceAllowedIPs: len(req.AllowedIPs) > 0,
	}

	if req.PresharedKey != nil {
		key, err := wgtypes.ParseKey(*req.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid preshared key: %w", err)
		}
		peerCfg.PresharedKey = &key
	}

	if len(req.AllowedIPs) > 0 {
		allowedIPs := make([]net.IPNet, 0, len(req.AllowedIPs))
		for _, ip := range req.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid allowed IP %s: %w", ip, err)
			}
			allowedIPs = append(allowedIPs, *ipNet)
		}
		peerCfg.AllowedIPs = allowedIPs
	}

	if req.PersistentKeepaliveInterval != nil {
		duration, err := time.ParseDuration(*req.PersistentKeepaliveInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid keepalive interval: %w", err)
		}
		peerCfg.PersistentKeepaliveInterval = &duration
	}

	if req.Endpoint != nil && *req.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", *req.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint: %w", err)
		}
		peerCfg.Endpoint = addr
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := c.ctrl.ConfigureDevice(d.Name, cfg); err != nil {
		return nil, err
	}

	return c.GetPeer(deviceName, urlSafePubKey)
}

// DeletePeer removes a peer from a device.
func (c *Client) DeletePeer(deviceName string, urlSafePubKey string) (*entity.Peer, error) {
	pubKey, err := decodeURLSafeKey(urlSafePubKey)
	if err != nil {
		return nil, err
	}

	peer, err := c.GetPeer(deviceName, urlSafePubKey)
	if err != nil {
		return nil, err
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey: *pubKey,
		Remove:    true,
	}

	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}

	if err := c.configure(deviceName, cfg); err != nil {
		return nil, err
	}

	return peer, nil
}

func deviceToEntity(d *wgtypes.Device) entity.Device {
	var totalReceive, totalTransmit int64
	for _, p := range d.Peers {
		totalReceive += p.ReceiveBytes
		totalTransmit += p.TransmitBytes
	}

	networks := getDeviceNetworks(d.Name)

	return entity.Device{
		Name:               d.Name,
		ListenPort:         int32(d.ListenPort),
		PublicKey:          d.PublicKey.String(),
		PrivateKey:         d.PrivateKey.String(),
		FirewallMark:       int32(d.FirewallMark),
		QuickOptions:       entity.QuickOptions{Addresses: networks},
		PeersCount:         int32(len(d.Peers)),
		TotalReceiveBytes:  totalReceive,
		TotalTransmitBytes: totalTransmit,
	}
}

func peerToEntity(p wgtypes.Peer) entity.Peer {
	allowedIPs := make([]string, len(p.AllowedIPs))
	for i, ip := range p.AllowedIPs {
		allowedIPs[i] = ip.String()
	}

	endpoint := ""
	if p.Endpoint != nil {
		endpoint = p.Endpoint.String()
	}

	presharedKey := ""
	if p.PresharedKey != EmptyKey {
		presharedKey = p.PresharedKey.String()
	}

	return entity.Peer{
		PublicKey:                   p.PublicKey.String(),
		URLSafePublicKey:            base64.URLEncoding.EncodeToString(p.PublicKey[:]),
		PresharedKey:                presharedKey,
		AllowedIPs:                  allowedIPs,
		LastHandshakeTime:           p.LastHandshakeTime,
		PersistentKeepaliveInterval: p.PersistentKeepaliveInterval.String(),
		Endpoint:                    endpoint,
		ReceiveBytes:                p.ReceiveBytes,
		TransmitBytes:               p.TransmitBytes,
	}
}

func decodeURLSafeKey(urlSafeKey string) (*wgtypes.Key, error) {
	// Handle both standard and URL-safe base64
	keyBytes, err := base64.URLEncoding.DecodeString(urlSafeKey)
	if err != nil {
		// Try standard base64 with URL-safe replacement
		keyBytes, err = base64.StdEncoding.DecodeString(
			strings.ReplaceAll(strings.ReplaceAll(urlSafeKey, "-", "+"), "_", "/"),
		)
		if err != nil {
			return nil, fmt.Errorf("invalid public key encoding: %w", err)
		}
	}

	if len(keyBytes) != wgtypes.KeyLen {
		return nil, fmt.Errorf("invalid key length")
	}

	var key wgtypes.Key
	copy(key[:], keyBytes)
	return &key, nil
}

func getDeviceNetworks(name string) []string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	networks := make([]string, len(addrs))
	for i, addr := range addrs {
		networks[i] = addr.String()
	}

	return networks
}

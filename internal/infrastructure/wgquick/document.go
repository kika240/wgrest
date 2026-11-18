package wgquick

import (
	"bufio"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/suquant/wgrest/internal/domain/entity"
)

// Config is a wg-quick config file that can be read, changed and written back
// without losing what this package does not manage: comments, key order,
// formatting of unchanged values and keys it does not know (SaveConfig, ...).
type Config struct {
	sections []*section
	// trailer holds the comments and blank lines after the last key of the
	// file. They describe the file, not its last peer.
	trailer []string
}

// section is one [Interface] or [Peer] block. The first section of a file has
// no header and holds what comes before the first block.
type section struct {
	// lead holds the comments and blank lines right above the header. A
	// comment above a [Peer] describes that peer, so it goes away with it.
	lead   []string
	header string
	lines  []string
}

const (
	interfaceHeader = "[Interface]"
	peerHeader      = "[Peer]"
)

// ParseConfig reads a wg-quick config file.
func ParseConfig(r io.Reader) (*Config, error) {
	cur := &section{}
	c := &Config{sections: []*section{cur}}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if isHeader(line) {
			next := &section{header: line}
			cur.lines, next.lead = splitAfterLastKey(cur.lines)
			c.sections = append(c.sections, next)
			cur = next
			continue
		}
		cur.lines = append(cur.lines, line)
	}
	cur.lines, c.trailer = splitAfterLastKey(cur.lines)

	return c, scanner.Err()
}

// Bytes renders the config file.
func (c *Config) Bytes() []byte {
	var lines []string
	for _, s := range c.sections {
		lines = append(lines, s.lead...)
		if s.header != "" {
			lines = append(lines, s.header)
		}
		lines = append(lines, s.lines...)
	}
	lines = append(lines, c.trailer...)
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// Options returns the wg-quick-only [Interface] settings.
func (c *Config) Options() entity.QuickOptions {
	iface := c.find(interfaceHeader)
	if iface == nil {
		return entity.QuickOptions{}
	}
	return entity.QuickOptions{
		Addresses: iface.list("Address"),
		DNS:       iface.list("DNS"),
		MTU:       int32(iface.number("MTU")),
		Table:     iface.value("Table"),
		PreUp:     iface.values("PreUp"),
		PostUp:    iface.values("PostUp"),
		PreDown:   iface.values("PreDown"),
		PostDown:  iface.values("PostDown"),
	}
}

// SetOptions replaces the wg-quick-only [Interface] settings.
func (c *Config) SetOptions(o entity.QuickOptions) {
	iface := c.iface()
	iface.setList("Address", o.Addresses)
	iface.setList("DNS", o.DNS)
	iface.setNumber("MTU", int64(o.MTU))
	iface.setValue("Table", o.Table)
	iface.setValues("PreUp", o.PreUp)
	iface.setValues("PostUp", o.PostUp)
	iface.setValues("PreDown", o.PreDown)
	iface.setValues("PostDown", o.PostDown)
}

// Device describes the interface as the file defines it, for an interface
// that is not running.
func (c *Config) Device(name string) entity.Device {
	d := entity.Device{Name: name, QuickOptions: c.Options()}
	if iface := c.find(interfaceHeader); iface != nil {
		d.PrivateKey = iface.value("PrivateKey")
		d.ListenPort = int32(iface.number("ListenPort"))
		d.FirewallMark = int32(iface.number("FwMark"))
	}
	return d
}

// SetRunning replaces what the kernel owns (keys, port, firewall mark and the
// peer list) with the running state, keeping the wg-quick settings.
func (c *Config) SetRunning(d *entity.Device, peers []entity.Peer) {
	iface := c.iface()
	iface.setValue("PrivateKey", d.PrivateKey)
	iface.setNumber("ListenPort", int64(d.ListenPort))
	iface.setNumber("FwMark", int64(d.FirewallMark))

	existing := map[string]*section{}
	var kept []*section
	for _, s := range c.sections {
		if isSection(s.header, peerHeader) {
			existing[s.value("PublicKey")] = s
		} else {
			kept = append(kept, s)
		}
	}

	for _, p := range peers {
		s, ok := existing[p.PublicKey]
		if !ok {
			s = &section{lead: []string{""}, header: peerHeader}
		}
		s.setValue("PublicKey", p.PublicKey)
		s.setValue("PresharedKey", p.PresharedKey)
		s.setList("AllowedIPs", p.AllowedIPs)
		s.setValue("Endpoint", p.Endpoint)
		s.setNumber("PersistentKeepalive", keepaliveSeconds(p.PersistentKeepaliveInterval))
		kept = append(kept, s)
	}
	c.sections = kept
}

// keepaliveSeconds converts the API's duration ("25s") to the whole seconds
// wg-quick expects.
func keepaliveSeconds(d string) int64 {
	v, err := time.ParseDuration(d)
	if err != nil {
		return 0
	}
	return int64(v / time.Second)
}

func (c *Config) find(header string) *section {
	for _, s := range c.sections {
		if isSection(s.header, header) {
			return s
		}
	}
	return nil
}

// iface returns the [Interface] section, adding one before any peer if the
// file has none.
func (c *Config) iface() *section {
	if s := c.find(interfaceHeader); s != nil {
		return s
	}
	s := &section{header: interfaceHeader}
	c.sections = slices.Insert(c.sections, 1, s)
	return s
}

func isHeader(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]")
}

func isSection(header, want string) bool {
	return strings.EqualFold(strings.TrimSpace(header), want)
}

// keyValue splits a "Key = Value" line. Like wg-quick, it ignores everything
// after a "#", so comments and blank lines have no key.
func keyValue(line string) (key, value string, ok bool) {
	t, _, _ := strings.Cut(line, "#")
	t = strings.TrimSpace(t)
	if t == "" {
		return "", "", false
	}
	k, v, ok := strings.Cut(t, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

func isKey(line, key string) bool {
	k, _, ok := keyValue(line)
	return ok && strings.EqualFold(k, key)
}

// splitAfterLastKey splits lines after the last "Key = Value" line.
func splitAfterLastKey(lines []string) (body, rest []string) {
	for i := len(lines) - 1; i >= 0; i-- {
		if _, _, ok := keyValue(lines[i]); ok {
			return lines[:i+1], lines[i+1:]
		}
	}
	return nil, lines
}

// values returns the value of each line with key, in order.
func (s *section) values(key string) []string {
	var out []string
	for _, l := range s.lines {
		if k, v, ok := keyValue(l); ok && strings.EqualFold(k, key) {
			out = append(out, v)
		}
	}
	return out
}

func (s *section) value(key string) string {
	if v := s.values(key); len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

// list returns a comma-separated key, which may also be repeated.
func (s *section) list(key string) []string {
	var out []string
	for _, v := range s.values(key) {
		for _, item := range strings.Split(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

// number accepts decimal and 0x-prefixed values, as wg does for FwMark.
func (s *section) number(key string) int64 {
	n, _ := strconv.ParseInt(s.value(key), 0, 64)
	return n
}

// setValues makes key hold exactly vals, one line each. Unchanged keys are
// left as written. The first existing line of key keeps its position; a new
// key goes after the last key of the section.
func (s *section) setValues(key string, vals []string) {
	if slices.Equal(s.values(key), vals) {
		return
	}

	at := -1
	var lines []string
	for _, l := range s.lines {
		if isKey(l, key) {
			if at < 0 {
				at = len(lines)
			}
			continue
		}
		lines = append(lines, l)
	}
	if at < 0 {
		body, _ := splitAfterLastKey(lines)
		at = len(body)
	}

	added := make([]string, len(vals))
	for i, v := range vals {
		added[i] = key + " = " + v
	}
	s.lines = slices.Insert(lines, at, added...)
}

func (s *section) setValue(key, v string) {
	if v == "" {
		s.setValues(key, nil)
		return
	}
	s.setValues(key, []string{v})
}

func (s *section) setList(key string, items []string) {
	if slices.Equal(s.list(key), items) {
		return
	}
	s.setValue(key, strings.Join(items, ", "))
}

func (s *section) setNumber(key string, n int64) {
	if n == 0 {
		s.setValues(key, nil)
		return
	}
	if s.number(key) == n {
		return
	}
	s.setValue(key, strconv.FormatInt(n, 10))
}

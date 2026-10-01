package license

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"sort"
	"strings"
)

// FingerprintFunc returns the machine fingerprint the verifier binds to.
type FingerprintFunc func() (string, error)

// MachineFingerprint computes a stable fingerprint of the local machine
// without any network access. It combines host-specific identifiers into a
// SHA-256 digest: the machine-id, the hostname, and the MAC addresses of
// the non-loopback network interfaces.
func MachineFingerprint() (string, error) {
	var parts []string

	if id, err := readMachineID(); err == nil && id != "" {
		parts = append(parts, "machine-id:"+id)
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		parts = append(parts, "hostname:"+h)
	}
	if macs, err := interfaceMACs(); err == nil && len(macs) > 0 {
		parts = append(parts, "macs:"+strings.Join(macs, ","))
	}

	if len(parts) == 0 {
		return "", ErrNoFingerprint
	}
	return FingerprintFromParts(parts...), nil
}

// ErrNoFingerprint is returned when no machine identifier can be read.
var ErrNoFingerprint = errNoFingerprint{}

type errNoFingerprint struct{}

func (errNoFingerprint) Error() string {
	return "license: no machine fingerprint available"
}

// FingerprintFromParts builds a fingerprint from the given components.
// It is used by MachineFingerprint and by tests that need a deterministic
// fingerprint source.
func FingerprintFromParts(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readMachineID reads the system machine-id on Linux. It falls back to the
// dbus machine-id location used by older distributions.
func readMachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	}
	return "", os.ErrNotExist
}

// interfaceMACs returns the MAC addresses of all up, non-loopback
// interfaces, sorted for determinism.
func interfaceMACs() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			continue
		}
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return macs, nil
}

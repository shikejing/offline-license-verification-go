package license

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
)

// Fingerprint 描述机器绑定信息。
type Fingerprint struct {
	Hostname  string   `json:"hostname"`
	MachineID string   `json:"machine_id"`
	MACs      []string `json:"macs"`
}

// CurrentFingerprint 采集本机指纹（纯本地，无网络）。
// 任何单项采集失败都容忍，留空即可。
func CurrentFingerprint() Fingerprint {
	return Fingerprint{
		Hostname:  hostname(),
		MachineID: machineID(),
		MACs:      macAddrs(),
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// machineID 读取 systemd machine-id 或 dbus machine-id。
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

// macAddrs 收集非回环网卡的 MAC 地址，排序去重保证稳定。
func macAddrs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) == 0 {
			continue
		}
		mac := strings.ToLower(ifc.HardwareAddr.String())
		if _, ok := seen[mac]; ok {
			continue
		}
		seen[mac] = struct{}{}
		out = append(out, mac)
	}
	sort.Strings(out)
	return out
}

// Hash 计算指纹的规范化散列，用于绑定比对。
// 序列化前对 MAC 排序去重，使同一机器的散列稳定。
func (f Fingerprint) Hash() string {
	macs := append([]string(nil), f.MACs...)
	sort.Strings(macs)
	norm := Fingerprint{
		Hostname:  f.Hostname,
		MachineID: f.MachineID,
		MACs:      macs,
	}
	if norm.MACs == nil {
		norm.MACs = []string{}
	}
	b, _ := json.Marshal(&norm)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

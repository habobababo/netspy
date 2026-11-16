package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// --------------------------------------------------------------------------
// Hilfsfunktionen
// --------------------------------------------------------------------------

func normMAC(v any) string {
	mac := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(pyStr(v))), "-", ":")
	if len(mac) == 17 {
		return mac
	}
	return ""
}

// isRandomMAC: lokal administrierte MAC (2. Hex-Ziffer 2/6/A/E) = private Adresse (iOS, Android, Windows).
func isRandomMAC(mac string) bool {
	return len(mac) == 17 && strings.ContainsRune("26ae", rune(strings.ToLower(mac)[1]))
}

// vlanOf: 192.168.<vlan>.x -> vlan, sonst 0 (= „Andere“); ok=false für Adressen, die ignoriert werden.
func vlanOf(ip string) (int, bool) {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil || strings.Contains(ip, ":") {
		return 0, false
	}
	a := addr.To4()
	if (a[0] == 169 && a[1] == 254) || a.Equal(net.IPv4zero) || a[0] >= 224 && a[0] <= 239 || strings.HasSuffix(ip, ".255") {
		return 0, false // 169.254.x.x (kein DHCP), 0.0.0.0, Multicast usw.
	}
	parts := strings.Split(ip, ".")
	prefix := strings.Split(subnetPrefix, ".")
	if len(parts) < len(prefix) {
		return 0, true
	}
	for i, p := range prefix {
		if parts[i] != p {
			return 0, true
		}
	}
	if len(parts) < 3 {
		return 0, true
	}
	third, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, true
	}
	for _, v := range vlans {
		if v == third {
			return third, true
		}
	}
	return 0, true
}

func vlanLabel(v int) string {
	if v == 0 {
		return "Andere"
	}
	if name := vlanNames[v]; name != "" {
		return fmt.Sprintf("VLAN %d · %s", v, name)
	}
	return fmt.Sprintf("VLAN %d", v)
}

func displayName(d *Device) string {
	for _, s := range []string{d.Name, ifStr(unifiUseNames, d.UnifiName), d.Hostname, d.IP, d.MAC} {
		if s != "" {
			return s
		}
	}
	return ""
}

func ifStr(c bool, s string) string {
	if c {
		return s
	}
	return ""
}

func ipSortKey(ip string) uint32 {
	a := net.ParseIP(ip)
	if a == nil || a.To4() == nil {
		return 0
	}
	return binary.BigEndian.Uint32(a.To4())
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// --------------------------------------------------------------------------
// Zugriff auf JSON-Antworten (map[string]any) mit den gleichen Regeln wie vorher in Python
// --------------------------------------------------------------------------

// pyStr wandelt JSON-Werte in Text um (Zahlen ohne „.0“, nil = "").
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return fmt.Sprint(v)
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// gs: erster „wahre“ Wert der Schlüssel als Text (wie m.get(a) or m.get(b) or "").
func gs(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && truthy(v) {
			return pyStr(v)
		}
	}
	return ""
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case bool:
		if x {
			return 1
		}
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	}
	return 0
}

func isYes(v any) bool {
	switch strings.ToLower(pyStr(v)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func mapsOf(v any) []map[string]any {
	var out []map[string]any
	for _, x := range asList(v) {
		if m := asMap(x); m != nil {
			out = append(out, m)
		}
	}
	return out
}

// --------------------------------------------------------------------------
// Formatierung
// --------------------------------------------------------------------------

func fmtBytes(n float64) string {
	for _, unit := range []string{"B", "kB", "MB", "GB", "TB"} {
		if math.Abs(n) < 1000 || unit == "TB" {
			if unit == "B" {
				return fmt.Sprintf("%d B", int64(n))
			}
			s := fmt.Sprintf("%.0f", n)
			if n < 100 {
				s = fmt.Sprintf("%.1f", n)
			}
			return strings.ReplaceAll(s, ".", ",") + " " + unit
		}
		n /= 1000
	}
	return ""
}

func fmtRate(n float64) string { return fmtBytes(n) + "/s" }

func fmtTime(ts int64, layout string) string { return time.Unix(ts, 0).Format(layout) }

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

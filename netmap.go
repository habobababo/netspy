package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// Netzplan (Reiter „Netz“): Geräte aus der Datenbank, Switches/APs und ihre Uplinks
// aus UniFi, Verbindungen (Switch-Port / WLAN) aus dem letzten Scan. Eigene Geräte,
// Kabel, Namen, Typen, Notizen und Positionen liegen in kv "netmap".
// --------------------------------------------------------------------------

type uniLink struct {
	Wired  bool
	SwMAC  string
	SwPort int
	ApMAC  string
	Essid  string
}

var (
	uniLinksMu sync.Mutex
	uniLinks   = map[string]uniLink{} // mac -> Verbindung aus dem letzten Scan
	netmapMu   sync.Mutex
	connRE     = regexp.MustCompile(`^(?:🔌\s*(.+?)(?:\s+Port\s+(\d+))?|📶\s*(.*?)\s*@\s*(.+?)(?:\s*\((-?\d+) dBm\))?)$`)
)

func setUniLinks(c map[string]uniClient) {
	m := make(map[string]uniLink, len(c))
	for mac, x := range c {
		m[mac] = uniLink{x.Wired, x.SwMAC, x.SwPort, x.ApMAC, x.Essid}
	}
	uniLinksMu.Lock()
	uniLinks = m
	uniLinksMu.Unlock()
}

// guessKind rät den Gerätetyp grob aus Name/Hersteller.
func guessKind(texts ...string) string {
	t := strings.ToLower(strings.Join(texts, " "))
	has := func(ws ...string) bool {
		for _, w := range ws {
			if strings.Contains(t, w) {
				return true
			}
		}
		return false
	}
	switch {
	case has("switch", "usw-", "usw ", "gs108", "gs308", "tl-sg"):
		return "switch"
	case has("access point", "u6-", "u6 ", "uap", "u7-", "nanohd", "unifi ap", "deco", "repeater"):
		return "ap"
	case has("iphone", "ipad", "android", "pixel", "galaxy", "handy", "phone", "xiaomi", "oneplus", "redmi", "tablet"):
		return "phone"
	case has("shelly", "tasmota", "sonoff", "esp-", "esp32", "esp8266", "espressif", "tuya", "hue", "zigbee", "echo",
		"alexa", "nest", "homematic", "tado", "smart", "meross", "wled", "home assistant", "homeassistant"):
		return "iot"
	case has("tv", "chromecast", "roku", "firetv", "fire tv", "appletv", "apple tv", "sonos", "playstation", "xbox",
		"nintendo", "receiver", "shield"):
		return "tv"
	case has("printer", "drucker", "brother", "epson", "canon", "laserjet", "officejet"):
		return "printer"
	case has("nas", "synology", "qnap", "truenas", "diskstation", "unraid"):
		return "nas"
	case has("opnsense", "pfsense", "firewall"):
		return "gateway"
	case has("fritz", "router", "speedport", "vodafone", "station"):
		return "router"
	case has("proxmox", "pve", "server", "docker", "lxc"):
		return "server"
	}
	return "client"
}

func speedLabel(mbit float64) string {
	if mbit >= 1000 {
		if math.Mod(mbit, 1000) == 0 {
			return fmt.Sprintf("%dG", int(mbit/1000))
		}
		return fmt.Sprintf("%.1fG", mbit/1000)
	}
	if mbit > 0 {
		return fmt.Sprintf("%dM", int(mbit))
	}
	return ""
}

func portLabel(port, speed float64) string {
	var parts []string
	if port != 0 {
		parts = append(parts, fmt.Sprintf("Port %d", int(port)))
	}
	if s := speedLabel(speed); s != "" {
		parts = append(parts, s)
	}
	return strings.Join(parts, " · ")
}

type node = map[string]any

type edge struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type graph struct {
	nodes map[string]node
	order []string
	edges []*edge
	byIP  map[string]string
	byMAC map[string]string
}

func newGraph() *graph {
	return &graph{nodes: map[string]node{}, byIP: map[string]string{}, byMAC: map[string]string{}}
}

func ns(n node, k string) string { s, _ := n[k].(string); return s }

func (g *graph) add(n node) node {
	id := ns(n, "id")
	if old, ok := g.nodes[id]; ok {
		return old
	}
	g.nodes[id] = n
	g.order = append(g.order, id)
	if mac := ns(n, "mac"); mac != "" {
		if _, ok := g.byMAC[mac]; !ok {
			g.byMAC[mac] = id
		}
	}
	if ip := ns(n, "ip"); ip != "" && ns(n, "kind") != "vlan" {
		if _, ok := g.byIP[ip]; !ok {
			g.byIP[ip] = id
		}
	}
	return n
}

func (g *graph) link(a, b, kind, label string) {
	if a == "" || b == "" || a == b {
		return
	}
	for _, e := range g.edges {
		if e.From == a && e.To == b {
			return
		}
	}
	g.edges = append(g.edges, &edge{From: a, To: b, Kind: kind, Label: label})
}

func infoList(n node) []string {
	l, _ := n["info"].([]string)
	return l
}

func (g *graph) merge(old, nw string) {
	o, n := g.nodes[old], g.nodes[nw]
	if o == nil || n == nil || old == nw {
		return
	}
	for _, k := range []string{"mac", "vlan", "model", "ip"} {
		if ns(n, k) == "" && ns(o, k) != "" {
			n[k] = o[k]
		}
	}
	n["info"] = append(append([]string{}, infoList(n)...), infoList(o)...)
	for _, e := range g.edges {
		if e.From == old {
			e.From = nw
		}
		if e.To == old {
			e.To = nw
		}
	}
	delete(g.nodes, old)
	for _, m := range []map[string]string{g.byIP, g.byMAC} {
		for k, v := range m {
			if v == old {
				m[k] = nw
			}
		}
	}
}

func (g *graph) hasUplink(id string) bool {
	for _, e := range g.edges {
		if e.To == id && e.Kind != "net" {
			return true
		}
	}
	return false
}

func (g *graph) findLabel(label, kind string) string {
	found := ""
	want := strings.ToLower(strings.TrimSpace(label))
	for _, id := range g.order {
		n := g.nodes[id]
		if n == nil || strings.ToLower(strings.TrimSpace(ns(n, "label"))) != want {
			continue
		}
		if ns(n, "kind") == kind {
			return id
		}
		if found == "" && ns(n, "kind") != "vlan" {
			found = id
		}
	}
	if found != "" {
		if k := ns(g.nodes[found], "kind"); k == "client" || k == "device" {
			g.nodes[found]["kind"] = kind
		}
	}
	return found
}

func unifiKind(t, model string) string {
	t = strings.ToLower(t)
	switch {
	case t == "ugw" || t == "udm" || t == "uxg":
		return "gateway"
	case t == "usw" || strings.HasPrefix(strings.ToUpper(model), "US"):
		return "switch"
	case t == "uap":
		return "ap"
	}
	return "device"
}

func status(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func buildNetmap() map[string]any {
	g, warnings := newGraph(), []string{}

	// 1) UniFi-Infrastruktur mit Uplinks
	var infra []map[string]any
	if unifi.enabled() {
		infra = unifi.deviceList()
		if _, _, _, ue := scanState(); ue != "" {
			warnings = append(warnings, "UniFi: "+ue)
		}
	}
	upstream := map[string]bool{}
	for _, d := range infra {
		mac := normMAC(d["mac"])
		if mac == "" {
			continue
		}
		info := []string{}
		if truthy(d["version"]) {
			info = append(info, "Firmware "+pyStr(d["version"]))
		}
		if truthy(d["num_sta"]) {
			info = append(info, pyStr(d["num_sta"])+" Clients")
		}
		g.add(node{"id": "mac:" + mac, "label": firstNonEmpty(gs(d, "name", "model"), mac),
			"kind": unifiKind(gs(d, "type"), gs(d, "model")), "ip": gs(d, "ip"), "mac": mac,
			"model": gs(d, "model"), "status": status(num(d["state"]) == 1), "source": "unifi", "info": info})
	}
	for _, d := range infra {
		mac, up := normMAC(d["mac"]), asMap(d["uplink"])
		upmac := normMAC(up["uplink_mac"])
		if mac == "" || upmac == "" || upmac == mac {
			continue
		}
		upstream[upmac] = true
		wifi := pyStr(up["type"]) == "wireless"
		if _, ok := g.nodes["mac:"+upmac]; !ok {
			g.add(node{"id": "mac:" + upmac, "label": "Uplink " + upmac, "kind": "router", "mac": upmac, "source": "unifi"})
		}
		kind, label := "wire", portLabel(num(up["uplink_remote_port"]), num(up["speed"]))
		if wifi {
			kind, label = "wifi", "Mesh"
		}
		g.link("mac:"+upmac, "mac:"+mac, kind, label)
	}

	// 2) alle erkannten Geräte, pro MAC der aktuellste Eintrag
	devs := listDevices()
	best := map[string]*Device{}
	for _, d := range devs {
		b := best[d.MAC]
		if b == nil || d.Online > b.Online || (d.Online == b.Online && d.lastSeen() > b.lastSeen()) {
			best[d.MAC] = d
		}
	}
	macs := make([]string, 0, len(best))
	for m := range best {
		macs = append(macs, m)
	}
	sort.SliceStable(macs, func(i, j int) bool {
		a, b := ipSortKey(best[macs[i]].IP), ipSortKey(best[macs[j]].IP)
		if a != b {
			return a < b
		}
		return macs[i] < macs[j]
	})
	for _, mac := range macs {
		d := best[mac]
		id := "mac:" + mac
		info := []string{}
		if d.Vendor != "" {
			info = append(info, "Hersteller: "+d.Vendor)
		}
		if d.Conn != "" {
			info = append(info, d.Conn)
		}
		if n, ok := g.nodes[id]; ok { // Switch/AP aus UniFi: nur ergänzen
			if d.Name != "" || strings.HasPrefix(ns(n, "label"), "Uplink ") {
				n["label"] = displayName(d)
			}
			if ns(n, "ip") == "" && d.IP != "" {
				n["ip"] = d.IP
				if _, ok := g.byIP[d.IP]; !ok {
					g.byIP[d.IP] = id
				}
			}
			n["vlan"] = vlanLabel(d.VLAN)
			n["dev_id"] = d.ID
			n["info"] = append(append([]string{}, infoList(n)...), info...)
			if upstream[mac] {
				n["status"] = status(d.Online == 1)
			}
			continue
		}
		name := displayName(d)
		g.add(node{"id": id, "label": name, "kind": guessKind(name, d.Hostname, d.Vendor), "ip": d.IP, "mac": mac,
			"vlan": vlanLabel(d.VLAN), "status": status(d.Online == 1), "source": "netwatch", "info": info, "dev_id": d.ID})
	}

	// 3) Verbindungen: erst strukturiert aus dem letzten Scan, sonst aus dem Text („🔌 Switch Port 3“)
	uniLinksMu.Lock()
	links := uniLinks
	uniLinksMu.Unlock()
	for _, mac := range macs {
		d := best[mac]
		id := "mac:" + mac
		if upstream[mac] || g.hasUplink(id) {
			continue
		}
		if l, ok := links[mac]; ok {
			if _, has := g.nodes["mac:"+l.SwMAC]; l.Wired && has {
				g.link("mac:"+l.SwMAC, id, "wire", portLabel(float64(l.SwPort), 0))
				continue
			}
			if _, has := g.nodes["mac:"+l.ApMAC]; !l.Wired && has {
				g.link("mac:"+l.ApMAC, id, "wifi", l.Essid)
				continue
			}
		}
		m := connRE.FindStringSubmatch(d.Conn)
		if m == nil {
			continue
		}
		if m[1] != "" {
			sw := g.findLabel(m[1], "switch")
			if sw == "" {
				sw = "sw:" + strings.ToLower(m[1])
				g.add(node{"id": sw, "label": m[1], "kind": "switch", "source": "netwatch"})
			}
			label := ""
			if m[2] != "" {
				label = "Port " + m[2]
			}
			g.link(sw, id, "wire", label)
		} else if m[4] != "" {
			ap := g.findLabel(m[4], "ap")
			if ap == "" {
				ap = "ap:" + strings.ToLower(m[4])
				g.add(node{"id": ap, "label": m[4], "kind": "ap", "source": "netwatch"})
			}
			g.link(ap, id, "wifi", m[3])
		}
	}

	// 4) VLANs als Netz-Knoten am Gateway (.1); Geräte ohne bekannte Verbindung hängen an ihrem VLAN
	usedSet := map[int]bool{}
	for _, d := range best {
		if d.VLAN != 0 {
			usedSet[d.VLAN] = true
		}
	}
	used := make([]int, 0, len(usedSet))
	for v := range usedSet {
		used = append(used, v)
	}
	sort.Ints(used)
	gwFor, gwByName := map[int]string{}, map[string]string{}
	for _, d := range devs {
		v := d.VLAN
		if v == 0 || d.IP != fmt.Sprintf("%s.%d.1", subnetPrefix, v) {
			continue
		}
		id := g.byMAC[d.MAC]
		if id == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(firstNonEmpty(d.Name, d.Hostname)))
		if key == "" {
			key = id
		}
		if first := gwByName[key]; first != "" && first != id {
			g.merge(id, first) // OPNsense mit eigener MAC je VLAN → ein Gerät
			id = first
		} else {
			gwByName[key] = id
		}
		gwFor[v] = id
		if n := g.nodes[id]; n != nil {
			if k := ns(n, "kind"); k == "client" || k == "device" || k == "router" {
				n["kind"] = "gateway"
			}
		}
	}
	for _, v := range used {
		vid := fmt.Sprintf("vlan:%d", v)
		g.add(node{"id": vid, "label": vlanLabel(v), "kind": "vlan", "ip": fmt.Sprintf("%s.%d.0/24", subnetPrefix, v), "source": "netwatch"})
		if gw := gwFor[v]; gw != "" && g.nodes[gw] != nil {
			g.link(gw, vid, "net", "")
		}
	}
	for _, mac := range macs {
		d := best[mac]
		id := g.byMAC[mac]
		n := g.nodes[id]
		if n == nil || d.VLAN == 0 || g.hasUplink(id) || ns(n, "kind") == "gateway" || ns(n, "kind") == "vlan" {
			continue
		}
		toVLAN := false
		for _, e := range g.edges {
			if e.From == id && strings.HasPrefix(e.To, "vlan:") {
				toVLAN = true
				break
			}
		}
		if !toVLAN {
			g.link(fmt.Sprintf("vlan:%d", d.VLAN), id, "net", "")
		}
	}
	for _, id := range append([]string{}, g.order...) { // Switches/APs ohne Uplink an ihr VLAN
		n := g.nodes[id]
		if n == nil || (ns(n, "kind") != "switch" && ns(n, "kind") != "ap") || g.hasUplink(id) || ns(n, "ip") == "" {
			continue
		}
		if v, ok := vlanOf(ns(n, "ip")); ok && v != 0 && usedSet[v] {
			g.link(fmt.Sprintf("vlan:%d", v), id, "net", "")
		}
	}

	nodes := []node{}
	for _, id := range g.order {
		if n, ok := g.nodes[id]; ok {
			nodes = append(nodes, n)
		}
	}
	edges := []*edge{}
	seen := map[string]bool{}
	for _, e := range g.edges {
		if g.nodes[e.From] == nil || g.nodes[e.To] == nil || e.From == e.To {
			continue
		}
		e.ID = "a:" + e.From + ">" + e.To
		if !seen[e.ID] {
			seen[e.ID] = true
			edges = append(edges, e)
		}
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
	return map[string]any{"nodes": nodes, "edges": edges, "warnings": warnings, "unifi": unifi.enabled(),
		"map": netmapLoad(), "updated": time.Now().Unix()}
}

// ---- Ergänzungen (kv "netmap") ----

func netmapLoad() map[string]any {
	var d map[string]any
	json.Unmarshal([]byte(kvGet("netmap", "{}")), &d)
	out := map[string]any{"pos": map[string]any{}, "nodes": []any{}, "edges": []any{}, "hide_nodes": []any{},
		"hide_edges": []any{}, "names": map[string]any{}, "kinds": map[string]any{}, "notes": map[string]any{}}
	for k, def := range out {
		switch def.(type) {
		case map[string]any:
			if v, ok := d[k].(map[string]any); ok {
				out[k] = v
			}
		case []any:
			if v, ok := d[k].([]any); ok {
				out[k] = v
			}
		}
	}
	return out
}

func netmapSave(data any) error {
	m, ok := data.(map[string]any)
	if !ok {
		return errors.New("Netzplan ungültig")
	}
	s := func(v any, n int) string {
		if v == nil {
			return ""
		}
		return truncRunes(pyStr(v), n)
	}
	pos := map[string]any{}
	for k, v := range asMap(m["pos"]) {
		l := asList(v)
		if len(l) < 2 {
			continue
		}
		x, okx := toFloat(l[0])
		y, oky := toFloat(l[1])
		if okx && oky {
			pos[s(k, 200)] = []float64{math.Round(x*10) / 10, math.Round(y*10) / 10}
		}
	}
	items := func(lst any, keys ...string) []map[string]string {
		out := []map[string]string{}
		for _, it := range mapsOf(lst) {
			if !truthy(it["id"]) {
				continue
			}
			x := map[string]string{"id": s(it["id"], 200)}
			for _, k := range keys {
				if truthy(it[k]) {
					x[k] = s(it[k], 300)
				}
			}
			out = append(out, x)
		}
		return out
	}
	strmap := func(v any) map[string]string {
		out := map[string]string{}
		for k, x := range asMap(v) {
			if truthy(x) {
				out[s(k, 200)] = s(x, 300)
			}
		}
		return out
	}
	strs := func(v any, n int) []string {
		out := []string{}
		for _, x := range asList(v) {
			out = append(out, s(x, n))
		}
		return out
	}
	doc := map[string]any{
		"pos":        pos,
		"nodes":      items(m["nodes"], "label", "kind", "ip", "note"),
		"edges":      items(m["edges"], "from", "to", "kind", "label"),
		"hide_nodes": strs(m["hide_nodes"], 200),
		"hide_edges": strs(m["hide_edges"], 400),
		"names":      strmap(m["names"]), "kinds": strmap(m["kinds"]), "notes": strmap(m["notes"]),
	}
	if len(doc["nodes"].([]map[string]string)) > 1000 || len(doc["edges"].([]map[string]string)) > 3000 || len(pos) > 5000 {
		return errors.New("Netzplan zu groß")
	}
	b, _ := json.Marshal(doc)
	netmapMu.Lock()
	defer netmapMu.Unlock()
	kvSet("netmap", string(b))
	return nil
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case bool:
		return num(x), true
	case string:
		var f float64
		_, err := fmt.Sscan(strings.TrimSpace(x), &f)
		return f, err == nil
	}
	return 0, false
}

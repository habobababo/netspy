package main

import (
	"context"
	"fmt"
	"math"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// Scanner
// --------------------------------------------------------------------------

var (
	scanMu     sync.Mutex
	stateMu    sync.Mutex
	lastScan   int64
	lastError  string
	scanDur    float64
	unifiError string
)

func scanState() (int64, string, float64, string) {
	stateMu.Lock()
	defer stateMu.Unlock()
	return lastScan, lastError, scanDur, unifiError
}

func ping(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(pingTimeout+2)*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(pingTimeout), ip).Run() == nil
}

type devKey struct {
	mac  string
	vlan int
}

type seenInfo struct {
	IP, Hostname, Vendor, Interface string
	ArpOK, UnifiOK                  bool
	UnifiName, Conn                 string
}

type devEvent struct {
	kind  string
	d     Device
	oldIP string
}

type move struct {
	d      *Device // nach dem Wechsel (neue MAC/VLAN)
	before Device
	info   *seenInfo
}

func notifyEvent(devID *int64, kind, text, tgText string, send bool) {
	tg := ""
	if send && tgToken != "" && tgChat != "" {
		tg = "queued"
	}
	eid := addEvent(devID, kind, text, tg)
	if send {
		tgSend(tgText, eid)
	}
}

func idp(id int64) *int64 { return &id }

func scanOnce() {
	if !scanMu.TryLock() {
		return
	}
	t0 := time.Now()
	defer func() {
		stateMu.Lock()
		lastScan = time.Now().Unix()
		scanDur = math.Round(time.Since(t0).Seconds()*10) / 10
		stateMu.Unlock()
		scanMu.Unlock()
	}()
	if err := doScan(t0.Unix()); err != nil {
		stateMu.Lock()
		lastError = err.Error()
		stateMu.Unlock()
		logError("Scan fehlgeschlagen: %s", err)
		return
	}
	stateMu.Lock()
	lastError = ""
	stateMu.Unlock()
}

func doScan(now int64) error {
	arp, err := opn.arp()
	if err != nil {
		return err
	}
	leases := opn.leases()
	leaseByMAC := map[string]lease{}
	for _, l := range leases {
		leaseByMAC[l.MAC] = l
	}

	// Für die Traffic-Zuordnung merken, an welchem Interface jede IP hängt
	intf := map[string]string{}
	for _, e := range arp {
		if i := gs(e, "intf"); i != "" {
			intf[strings.TrimSpace(gs(e, "ip"))] = i
		}
	}
	setArpIntf(intf)

	// Was die Firewall gerade sieht: (mac, vlan) -> info (Reihenfolge wie gemeldet)
	seen := map[devKey]*seenInfo{}
	var seenOrder []devKey
	put := func(k devKey, info *seenInfo) {
		if _, ok := seen[k]; !ok {
			seenOrder = append(seenOrder, k)
		}
		seen[k] = info
	}
	for _, e := range arp {
		mac := normMAC(e["mac"])
		ip := strings.TrimSpace(gs(e, "ip"))
		if mac == "" || ip == "" {
			continue
		}
		if !includeFirewall && isYes(e["permanent"]) {
			continue
		}
		if mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		v, ok := vlanOf(ip)
		if !ok {
			continue
		}
		put(devKey{mac, v}, &seenInfo{
			IP: ip, Hostname: firstNonEmpty(gs(e, "hostname"), leaseByMAC[mac].Hostname), Vendor: gs(e, "manufacturer"),
			Interface: gs(e, "intf_description", "intf"), ArpOK: !isYes(e["expired"]),
		})
	}
	// Leases ergänzen (Geräte mit Lease, aber ohne ARP-Eintrag)
	for _, l := range leases {
		v, ok := vlanOf(l.IP)
		if !ok {
			continue
		}
		k := devKey{l.MAC, v}
		if _, has := seen[k]; !has {
			put(k, &seenInfo{IP: l.IP, Hostname: l.Hostname})
		}
	}
	// UniFi-Clients: verbunden = online, plus Aliasname und Verbindung (AP/SSID/Switch-Port)
	var uni map[string]uniClient
	if unifi.enabled() {
		c, err := unifi.clients()
		if err != nil {
			stateMu.Lock()
			unifiError = err.Error()
			stateMu.Unlock()
			logWarn("UniFi-Abfrage fehlgeschlagen: %v", err)
		} else {
			uni = c
			setUniLinks(c)
			stateMu.Lock()
			unifiError = ""
			stateMu.Unlock()
		}
	}
	uniMACs := make([]string, 0, len(uni))
	for m := range uni {
		uniMACs = append(uniMACs, m)
	}
	sort.Strings(uniMACs)
	for _, mac := range uniMACs {
		c := uni[mac]
		if c.IP == "" {
			continue
		}
		v, ok := vlanOf(c.IP)
		if !ok {
			continue
		}
		k := devKey{mac, v}
		info := seen[k]
		if info == nil {
			info = &seenInfo{IP: c.IP, Hostname: c.Hostname, Vendor: c.Vendor}
			put(k, info)
		}
		info.UnifiOK = true
		info.UnifiName = c.Name
		info.Conn = c.Conn
		if info.Hostname == "" {
			info.Hostname = c.Hostname
		}
		if info.Vendor == "" {
			info.Vendor = c.Vendor
		}
	}

	known := map[devKey]*Device{}
	var knownOrder []devKey
	for _, d := range listDevices() {
		k := devKey{d.MAC, d.VLAN}
		if _, ok := known[k]; !ok {
			knownOrder = append(knownOrder, k)
		}
		known[k] = d
	}
	firstScan := len(known) == 0
	removeKey := func(k devKey) {
		delete(known, k)
		for i, x := range knownOrder {
			if x == k {
				knownOrder = append(knownOrder[:i], knownOrder[i+1:]...)
				break
			}
		}
	}

	// Neue Geräte anlegen – vorher prüfen, ob es ein bekanntes Gerät ist, das nur
	// das WLAN/VLAN gewechselt hat oder eine neue private MAC verwendet
	var newDevices []*Device
	var moves []move
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, key := range seenOrder {
		info := seen[key]
		if _, ok := known[key]; ok {
			continue
		}
		mac, v := key.mac, key.vlan
		host := strings.ToLower(strings.TrimSpace(info.Hostname))
		uname := strings.ToLower(strings.TrimSpace(info.UnifiName))
		sameDevice := func(k devKey, d *Device) bool {
			if _, active := seen[k]; active { // alter Eintrag ist gerade selbst aktiv -> anderes Gerät
				return false
			}
			if k.mac == mac { // gleiche MAC, anderes VLAN (z. B. zweites WLAN)
				return true
			}
			if mergeRandomMAC && isRandomMAC(mac) && (host != "" || uname != "") {
				return (host != "" && strings.ToLower(strings.TrimSpace(d.Hostname)) == host) ||
					(uname != "" && strings.ToLower(strings.TrimSpace(d.UnifiName)) == uname)
			}
			return false
		}
		var old *Device
		for _, k := range knownOrder {
			d := known[k]
			if !sameDevice(k, d) {
				continue
			}
			// bevorzugt gleiche MAC, sonst zuletzt gesehenes Gerät
			if old == nil || better(d, old, mac) {
				old = d
			}
		}
		if old != nil {
			oldKey := devKey{old.MAC, old.VLAN}
			if _, err := tx.Exec("UPDATE devices SET mac=?, vlan=? WHERE id=?", mac, v, old.ID); err == nil {
				removeKey(oldKey)
				before := *old
				old.MAC, old.VLAN = mac, v
				moves = append(moves, move{old, before, info})
				known[key] = old
				knownOrder = append(knownOrder, key)
				continue
			}
		}
		watch := 0
		if watchDefault {
			watch = 1
		}
		res, err := tx.Exec("INSERT INTO devices(mac,vlan,ip,hostname,vendor,interface,unifi_name,conn,first_seen,"+
			"last_seen,online,fails,watch,changed_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,0,?,?)",
			mac, v, info.IP, info.Hostname, info.Vendor, info.Interface, info.UnifiName, info.Conn, now, nil, watch, now)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("Gerät anlegen: %w", err)
		}
		id, _ := res.LastInsertId()
		d, err := scanDevice(tx.QueryRow("SELECT "+devCols+" FROM devices WHERE id=?", id))
		if err != nil {
			tx.Rollback()
			return err
		}
		known[key] = d
		knownOrder = append(knownOrder, key)
		newDevices = append(newDevices, d)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	movedIDs := map[int64]bool{}
	for _, m := range moves {
		movedIDs[m.d.ID] = true
	}

	// Online-Prüfung
	pingOK := map[devKey]bool{}
	if onlineMode == "ping" || onlineMode == "ping_or_arp" {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, max(1, pingWorkers))
		for _, k := range knownOrder {
			ip := known[k].IP
			if s := seen[k]; s != nil && s.IP != "" {
				ip = s.IP
			}
			if ip == "" {
				continue
			}
			wg.Add(1)
			go func(k devKey, ip string) {
				defer wg.Done()
				sem <- struct{}{}
				ok := ping(ip)
				<-sem
				mu.Lock()
				pingOK[k] = ok
				mu.Unlock()
			}(k, ip)
		}
		wg.Wait()
	}

	var events []devEvent
	tx, err = db.Begin()
	if err != nil {
		return err
	}
	for _, key := range knownOrder {
		d := known[key]
		info := seen[key]
		arpOK := info != nil && info.ArpOK
		uniOK := info != nil && info.UnifiOK
		var alive bool
		switch onlineMode {
		case "arp":
			alive = arpOK || uniOK
		case "ping":
			alive = pingOK[key] || uniOK
		default:
			alive = pingOK[key] || arpOK || uniOK
		}
		fails := 0
		if !alive {
			fails = d.Fails + 1
		}
		online, changed := d.Online, d.ChangedAt
		if alive && online == 0 {
			online, changed = 1, idp(now)
			if d.LastSeen != nil { // nicht beim allerersten Sehen melden
				events = append(events, devEvent{kind: "online", d: *d})
			}
		} else if !alive && online == 1 && fails >= offlineAfter {
			online, changed = 0, idp(now)
			events = append(events, devEvent{kind: "offline", d: *d})
		}
		sets := []string{"online=?", "fails=?", "changed_at=?"}
		args := []any{online, fails, nullID(changed)}
		if alive {
			sets, args = append(sets, "last_seen=?"), append(args, now)
		}
		if info != nil {
			sets, args = append(sets, "ip=?"), append(args, info.IP)
			for _, f := range [][2]string{{"hostname", info.Hostname}, {"vendor", info.Vendor}, {"interface", info.Interface},
				{"unifi_name", info.UnifiName}, {"conn", info.Conn}} {
				if f[1] != "" {
					sets, args = append(sets, f[0]+"=?"), append(args, f[1])
				}
			}
		}
		if info != nil && d.IP != "" && info.IP != d.IP && !movedIDs[d.ID] {
			nd := *d
			nd.IP = info.IP
			events = append(events, devEvent{kind: "ipchange", d: nd, oldIP: d.IP})
		}
		if _, err := tx.Exec("UPDATE devices SET "+strings.Join(sets, ",")+" WHERE id=?", append(args, d.ID)...); err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if firstScan && len(newDevices) > 0 {
		// Erster Scan: eine Zusammenfassung statt einer Nachricht pro Gerät
		perVLAN := map[int]int{}
		for _, d := range newDevices {
			addEvent(idp(d.ID), "new", fmt.Sprintf("Erfasst beim ersten Scan: %s (%s)", displayName(d), d.IP), "")
			perVLAN[d.VLAN]++
		}
		vs := make([]int, 0, len(perVLAN))
		for v := range perVLAN {
			vs = append(vs, v)
		}
		sort.Slice(vs, func(i, j int) bool { return vlanSort(vs[i]) < vlanSort(vs[j]) })
		var lines []string
		for _, v := range vs {
			lines = append(lines, fmt.Sprintf("%s: %d", esc(vlanLabel(v)), perVLAN[v]))
		}
		notifyEvent(nil, "info", fmt.Sprintf("Erster Scan: %d Geräte erfasst", len(newDevices)),
			fmt.Sprintf("📋 <b>NetWatch gestartet</b>\n%d Geräte erfasst:\n", len(newDevices))+strings.Join(lines, "\n")+
				"\n\nAb jetzt kommt bei jedem neuen Gerät eine Nachricht.", notifyNew)
	} else {
		for _, d := range newDevices {
			rnd := isRandomMAC(d.MAC)
			msg := fmtNewDevice(d)
			text := fmt.Sprintf("Neues Gerät: %s (%s)", displayName(d), d.IP)
			if rnd {
				msg += "\n\nℹ️ <i>Private (zufällige) MAC-Adresse – kann auch ein bekanntes Gerät sein, " +
					"das eine neue Adresse verwendet.</i>"
				text += " · private MAC"
			}
			notifyEvent(idp(d.ID), "new", text, msg, notifyNew && (notifyRandomMAC || !rnd))
		}
	}
	for _, m := range moves {
		d := *m.d
		if m.info.IP != "" {
			d.IP = m.info.IP
		}
		if m.info.Conn != "" {
			d.Conn = m.info.Conn
		}
		if m.info.Hostname != "" {
			d.Hostname = m.info.Hostname
		}
		var parts, tgParts []string
		if m.before.VLAN != d.VLAN {
			parts = append(parts, vlanLabel(m.before.VLAN)+" → "+vlanLabel(d.VLAN))
			tgParts = append(tgParts, "Vorher: "+esc(vlanLabel(m.before.VLAN))+" · "+esc(m.before.IP))
		}
		if m.before.MAC != d.MAC {
			parts = append(parts, "neue private MAC "+m.before.MAC+" → "+d.MAC)
			tgParts = append(tgParts, "Vorherige MAC: <code>"+esc(m.before.MAC)+"</code>")
		}
		kind, title := "macchange", "🔄 <b>Neue private MAC</b>"
		if m.before.VLAN != d.VLAN {
			kind, title = "vlanchange", "🔀 <b>Wechselt WLAN/VLAN</b>"
		}
		notifyEvent(idp(d.ID), kind, displayName(&d)+": "+strings.Join(parts, ", "),
			title+"\n"+fmtDevice(&d)+"\n"+strings.Join(tgParts, "\n"), d.Watch != 0)
	}
	for _, e := range events {
		d := e.d
		switch e.kind {
		case "online":
			notifyEvent(idp(d.ID), e.kind, displayName(&d)+" ist online", "🟢 <b>Online</b>\n"+fmtDevice(&d), d.Watch != 0)
		case "offline":
			notifyEvent(idp(d.ID), e.kind, displayName(&d)+" ist offline", "🔴 <b>Offline</b>\n"+fmtDevice(&d), d.Watch != 0)
		case "ipchange":
			notifyEvent(idp(d.ID), e.kind, fmt.Sprintf("%s: IP %s → %s", displayName(&d), e.oldIP, d.IP),
				fmt.Sprintf("🔁 <b>IP geändert</b> %s → %s\n", esc(e.oldIP), esc(d.IP))+fmtDevice(&d), d.Watch != 0)
		}
	}
	logInfo("Scan: %d ARP, %d Leases, %d Geräte, %d neu", len(arp), len(leases), len(known), len(newDevices))
	return nil
}

// better: d ist ein besserer Kandidat als cur (gleiche MAC zuerst, dann zuletzt gesehen).
func better(d, cur *Device, mac string) bool {
	a, b := d.MAC == mac, cur.MAC == mac
	if a != b {
		return a
	}
	return d.lastSeen() > cur.lastSeen()
}

func vlanSort(v int) int {
	if v == 0 {
		return 999
	}
	return v
}

func scannerLoop() {
	for {
		scanOnce()
		time.Sleep(time.Duration(scanInterval) * time.Second)
	}
}

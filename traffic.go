package main

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// Traffic
// --------------------------------------------------------------------------
//
// Live: /api/diagnostics/traffic/top/<interfaces> (iftop auf der Firewall) liefert pro Adresse die
// aktuelle Rate. Daraus werden alle TRAFFIC_INTERVAL Sekunden Bytes hochgerechnet (Rate × Zeit)
// und pro Gerät und Stunde in SQLite addiert. Ist Insight (Netflow, „Capture local“) aktiv, werden
// abgeschlossene Stunden durch die genaueren Netflow-Summen ersetzt.
//
// Die Firewall sieht nur Verkehr, der über sie läuft: ins Internet und zwischen VLANs –
// nicht zwischen zwei Geräten im selben VLAN.

type alertSt struct {
	Since   *float64 `json:"since"`
	Alerted bool     `json:"alerted"`
	Peak    float64  `json:"peak"`
}

type TrafficStatus struct {
	Enabled        bool     `json:"enabled"`
	Error          string   `json:"error"`
	Last           int64    `json:"last"`
	Duration       float64  `json:"duration"`
	Interfaces     []string `json:"interfaces"`
	Hosts          int      `json:"hosts"`
	Interval       int      `json:"interval"`
	Insight        string   `json:"insight"`
	InsightError   string   `json:"insight_error"`
	InsightLast    int64    `json:"-"`
	AlertMBs       float64  `json:"alert_mbs"`
	AlertMinutes   int      `json:"alert_minutes"`
	AlertDirection string   `json:"alert_direction"`
}

var (
	trMu       sync.Mutex
	arpIntf    = map[string]string{}    // ip -> Interface-Gerätename aus der ARP-Tabelle (z. B. vlan0.20)
	liveRates  = map[int64][2]float64{} // device_id -> (rx B/s, tx B/s)
	alertState = map[int64]*alertSt{}   // device_id -> Alarmzustand
	trState    = TrafficStatus{Interfaces: []string{}, Insight: "noch nicht geprüft"}
	ifCache    map[string]ifInfo
	ifCacheTS  time.Time
	lastPoll   time.Time
)

func init() {
	if trafficInsight == "false" {
		trState.Insight = "aus"
	}
}

func setArpIntf(m map[string]string) {
	trMu.Lock()
	arpIntf = m
	trMu.Unlock()
}

func arpIntfSnapshot() map[string]string {
	trMu.Lock()
	defer trMu.Unlock()
	return arpIntf
}

func liveSnapshot() map[int64][2]float64 {
	trMu.Lock()
	defer trMu.Unlock()
	out := make(map[int64][2]float64, len(liveRates))
	for k, v := range liveRates {
		out[k] = v
	}
	return out
}

func alertActive(id int64) bool {
	trMu.Lock()
	defer trMu.Unlock()
	st := alertState[id]
	return st != nil && st.Alerted
}

func trafficStatus() TrafficStatus {
	trMu.Lock()
	st := trState
	st.Interfaces = append([]string{}, trState.Interfaces...)
	trMu.Unlock()
	st.Enabled, st.Interval = trafficEnabled, trafficInterval
	st.AlertMBs, st.AlertMinutes, st.AlertDirection = trafficAlertMBs, trafficAlertMinutes, trafficAlertDirection
	return st
}

func forgetDevice(id int64) {
	trMu.Lock()
	delete(liveRates, id)
	delete(alertState, id)
	trMu.Unlock()
}

// ---- Zeit ----

var ranges = map[string]struct {
	kind  string // h = Stundenwerte, d = Tageswerte
	size  int64
	count int
}{
	"24h": {"h", 3600, 24},
	"7d":  {"h", 6 * 3600, 28},
	"30d": {"d", 86400, 30},
}

// dayStart: lokale Mitternacht (Container-TZ) des Zeitpunkts.
func dayStart(ts int64) int64 {
	t := time.Unix(ts, 0)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local).Unix()
}

func nextDay(ts int64) int64 {
	t := time.Unix(ts, 0)
	return time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.Local).Unix()
}

// lastDays: lokale Mitternachten der letzten count Tage (heute eingeschlossen), aufsteigend.
func lastDays(now int64, count int) []int64 {
	t := time.Unix(now, 0)
	out := make([]int64, count)
	for i := 0; i < count; i++ {
		out[i] = time.Date(t.Year(), t.Month(), t.Day()-(count-1-i), 0, 0, 0, 0, time.Local).Unix()
	}
	return out
}

// rangeWindow: (Tabelle, Startzeiten der Balken, Ende).
func rangeWindow(rng string, now int64) (string, []int64, int64) {
	r := ranges[rng]
	if r.kind == "h" && r.size == 3600 {
		end := now - now%3600 + 3600
		starts := make([]int64, r.count)
		for i := range starts {
			starts[i] = end - int64(r.count-i)*3600
		}
		return "h", starts, end
	}
	if r.kind == "h" { // 6-h-Blöcke ab lokaler Mitternacht
		days := lastDays(now, int(int64(r.count)*r.size/86400))
		var starts []int64
		for _, d := range days {
			t := time.Unix(d, 0)
			for h := 0; h < 24; h += int(r.size / 3600) {
				starts = append(starts, time.Date(t.Year(), t.Month(), t.Day(), h, 0, 0, 0, time.Local).Unix())
			}
		}
		return "h", starts, nextDay(days[len(days)-1])
	}
	days := lastDays(now, r.count)
	return "d", days, nextDay(days[len(days)-1])
}

// ---- Abfrage ----

func trafficIfaces() (map[string]ifInfo, error) {
	trMu.Lock()
	cached, ts := ifCache, ifCacheTS
	trMu.Unlock()
	if len(cached) > 0 && time.Since(ts) < 600*time.Second {
		return cached, nil
	}
	info, err := opn.trafficInterfaces()
	if err != nil {
		return nil, err
	}
	trMu.Lock()
	ifCache, ifCacheTS = info, time.Now()
	trMu.Unlock()
	return info, nil
}

// pickIfaces: TRAFFIC_INTERFACES oder alle Interfaces, an denen Geräte hängen.
func pickIfaces(info map[string]ifInfo) []string {
	if len(trafficInterfaces) > 0 {
		return trafficInterfaces
	}
	used := map[string]bool{}
	for _, v := range arpIntfSnapshot() {
		used[v] = true
	}
	var keys []string
	for k, v := range info {
		if used[v.Device] || used[k] {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		for k, v := range info {
			if !strings.HasPrefix(k, "wan") && !strings.HasPrefix(k, "lo") && !strings.Contains(strings.ToLower(v.Name), "wan") {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

// parseTop: Top-Talker-Antwort -> ip -> (rx B/s, tx B/s).
//
// Ein Gerät kann auf mehreren Interfaces auftauchen (Verkehr zwischen VLANs sieht die Firewall auf
// beiden Seiten). Genommen wird der Eintrag vom eigenen Interface laut ARP-Tabelle, sonst der
// größte – nie die Summe, sonst würde Inter-VLAN-Verkehr doppelt gezählt.
func parseTop(res map[string]any, info map[string]ifInfo) map[string][2]float64 {
	dev2key := map[string]string{}
	for k, v := range info {
		if v.Device != "" {
			dev2key[v.Device] = k
		}
	}
	type cand struct {
		idents map[string]bool
		rx, tx float64
	}
	cands := map[string][]cand{}
	ifnames := make([]string, 0, len(res))
	for k := range res {
		ifnames = append(ifnames, k)
	}
	sort.Strings(ifnames)
	for _, ifname := range ifnames {
		block := asMap(res[ifname])
		if block == nil {
			continue
		}
		idents := map[string]bool{}
		for _, s := range []string{ifname, info[ifname].Device, dev2key[ifname]} {
			if s != "" {
				idents[s] = true
			}
		}
		for _, r := range mapsOf(block["records"]) {
			ip := strings.TrimSpace(gs(r, "address"))
			if ip == "" {
				continue
			}
			rin, rout := num(r["rate_bits_in"])/8, num(r["rate_bits_out"])/8
			rx, tx := rin, rout
			if trafficSwap {
				rx, tx = rout, rin
			}
			cands[ip] = append(cands[ip], cand{idents, rx, tx})
		}
	}
	own := arpIntfSnapshot()
	out := map[string][2]float64{}
	for ip, lst := range cands {
		var best *cand
		if o := own[ip]; o != "" {
			for i := range lst {
				if lst[i].idents[o] {
					best = &lst[i]
					break
				}
			}
		}
		if best == nil {
			for i := range lst {
				if best == nil || lst[i].rx+lst[i].tx > best.rx+best.tx {
					best = &lst[i]
				}
			}
		}
		out[ip] = [2]float64{best.rx, best.tx}
	}
	return out
}

// devicesByIP: IP -> Gerät (bei doppelten IPs: online vor offline, dann zuletzt gesehen).
func devicesByIP(devs []*Device) map[string]*Device {
	s := append([]*Device(nil), devs...)
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Online != s[j].Online {
			return s[i].Online < s[j].Online
		}
		return s[i].lastSeen() < s[j].lastSeen()
	})
	out := map[string]*Device{}
	for _, d := range s {
		if d.IP != "" {
			out[d.IP] = d
		}
	}
	return out
}

func addTraffic(amounts map[int64][2]float64, ts int64) {
	hour := ts - ts%3600
	tx, err := db.Begin()
	if err != nil {
		logWarn("Traffic speichern: %v", err)
		return
	}
	var ids []int64
	for dev, v := range amounts {
		rx, txb := int64(v[0]), int64(v[1])
		if v[0] < 1 && v[1] < 1 {
			continue
		}
		if _, err := tx.Exec("INSERT INTO traffic_hourly(device, ts, rx, tx, src) VALUES(?,?,?,?,'live') "+
			"ON CONFLICT(device, ts) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx "+
			"WHERE traffic_hourly.src = 'live'", dev, hour, rx, txb); err != nil { // Insight-Stunden nicht überschreiben
			logWarn("Traffic speichern: %v", err)
			continue
		}
		ids = append(ids, dev)
	}
	if len(ids) == 0 {
		tx.Rollback()
		return
	}
	if err := recomputeDailyTx(tx, ids, []int64{dayStart(hour)}); err != nil {
		logWarn("Tageswerte: %v", err)
	}
	if err := tx.Commit(); err != nil {
		logWarn("Traffic speichern: %v", err)
	}
}

// recomputeDailyTx: Tageswerte aus den Stundenwerten neu berechnen (hält beide Tabellen konsistent).
func recomputeDailyTx(tx *sql.Tx, ids []int64, days []int64) error {
	if len(ids) == 0 {
		return nil
	}
	in := sqlInList(ids)
	for _, day := range days {
		if _, err := tx.Exec("INSERT OR REPLACE INTO traffic_daily(device, ts, rx, tx) "+
			"SELECT device, ?, SUM(rx), SUM(tx) FROM traffic_hourly "+
			"WHERE ts >= ? AND ts < ? AND device IN ("+in+") GROUP BY device", day, day, nextDay(day)); err != nil {
			return err
		}
	}
	return nil
}

func trafficPoll() error {
	t0 := time.Now()
	info, err := trafficIfaces()
	if err != nil {
		return err
	}
	if len(info) == 0 {
		return errors.New("OPNsense liefert keine Interfaces unter /api/diagnostics/traffic/interface")
	}
	keys := pickIfaces(info)
	var unknown []string
	for _, k := range keys {
		if _, ok := info[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		avail := make([]string, 0, len(info))
		for k := range info {
			avail = append(avail, k)
		}
		sort.Strings(avail)
		return fmt.Errorf("TRAFFIC_INTERFACES: unbekannte Interfaces %s – verfügbar: %s",
			strings.Join(unknown, ", "), strings.Join(avail, ", "))
	}
	res, err := opn.trafficTop(keys)
	if err != nil {
		return err
	}
	rates := parseTop(res, info)
	now := time.Now()
	devs := listDevices()
	byIP := devicesByIP(devs)
	live := map[int64][2]float64{}
	for ip, r := range rates {
		d := byIP[ip]
		if d == nil {
			continue // Adressen im Internet / unbekannte Geräte
		}
		cur := live[d.ID]
		live[d.ID] = [2]float64{cur[0] + r[0], cur[1] + r[1]}
	}
	trMu.Lock()
	dt := float64(trafficInterval)
	if !lastPoll.IsZero() {
		dt = now.Sub(lastPoll).Seconds()
	}
	dt = math.Max(1, math.Min(dt, 3*float64(trafficInterval))) // nach Ausfällen nicht riesig hochrechnen
	lastPoll = now
	liveRates = live
	trMu.Unlock()
	amounts := map[int64][2]float64{}
	for id, r := range live {
		amounts[id] = [2]float64{r[0] * dt, r[1] * dt}
	}
	addTraffic(amounts, now.Unix())
	names := make([]string, len(keys))
	for i, k := range keys {
		names[i] = fmt.Sprintf("%s (%s)", info[k].Name, k)
	}
	trMu.Lock()
	trState.Error = ""
	trState.Last = now.Unix()
	trState.Duration = math.Round(time.Since(t0).Seconds()*10) / 10
	trState.Hosts = len(live)
	trState.Interfaces = names
	if len(res) == 0 {
		trState.Error = "Top Talker lieferte keine Daten – Interfaces prüfen (abgefragt: " + strings.Join(keys, ", ") + ")"
	}
	trMu.Unlock()
	checkAlerts(devs, float64(now.Unix()))
	return nil
}

// checkAlerts: Alarm, wenn ein beobachtetes Gerät TRAFFIC_ALERT_MINUTES lang über der Schwelle liegt.
func checkAlerts(devs []*Device, now float64) {
	what := map[string]string{"down": "Download", "up": "Upload"}[trafficAlertDirection]
	if what == "" {
		what = "Traffic"
	}
	type note struct {
		id       int64
		text, tg string
	}
	var notes []note
	trMu.Lock()
	for _, d := range devs {
		lim := trafficAlertMBs
		if d.TrafficLimit != nil {
			lim = *d.TrafficLimit
		}
		if d.Watch == 0 || lim <= 0 {
			delete(alertState, d.ID)
			continue
		}
		r := liveRates[d.ID]
		val := r[0] + r[1]
		switch trafficAlertDirection {
		case "down":
			val = r[0]
		case "up":
			val = r[1]
		}
		thr := lim * 1e6
		st := alertState[d.ID]
		if st == nil {
			st = &alertSt{}
			alertState[d.ID] = st
		}
		if val >= thr {
			if st.Since == nil {
				n := now
				st.Since = &n
			}
			st.Peak = math.Max(st.Peak, val)
			if !st.Alerted && now-*st.Since >= float64(trafficAlertMinutes*60) {
				st.Alerted = true
				mins := int(math.Round((now - *st.Since) / 60))
				notes = append(notes, note{d.ID,
					fmt.Sprintf("%s: hoher %s seit %d min (%s)", displayName(d), what, mins, fmtRate(val)),
					fmt.Sprintf("⚠️ <b>Hoher %s</b> seit %d min\n%s\nJetzt: ↓ %s · ↑ %s\nSchwelle: %s",
						what, mins, fmtDevice(d), fmtRate(r[0]), fmtRate(r[1]), fmtRate(thr))})
			}
		} else if val < thr*0.8 { // etwas Hysterese gegen Flattern
			if st.Alerted {
				mins := int(math.Round((now - *st.Since) / 60))
				notes = append(notes, note{d.ID,
					fmt.Sprintf("%s: %s wieder normal (nach %d min, Spitze %s)", displayName(d), what, mins, fmtRate(st.Peak)),
					fmt.Sprintf("✅ <b>%s wieder normal</b>\n%s – nach %d min, Spitze %s", what, esc(displayName(d)), mins, fmtRate(st.Peak))})
			}
			alertState[d.ID] = &alertSt{}
		}
	}
	trMu.Unlock()
	for _, n := range notes {
		notifyEvent(idp(n.id), "traffic", n.text, n.tg, true)
	}
}

// insightImport: abgeschlossene Stunden aus Insight übernehmen (genauer als die Live-Hochrechnung).
func insightImport() error {
	if trafficInsight == "false" {
		return nil
	}
	if trafficInsight == "auto" && opn.netflowEnabled() == 0 {
		trMu.Lock()
		trState.Insight = "nicht aktiviert (Reporting → NetFlow → „Capture local“)"
		trState.InsightError = ""
		trMu.Unlock()
		return nil
	}
	trMu.Lock()
	info := ifCache
	trMu.Unlock()
	dev2key := map[string]string{}
	for k, v := range info {
		if v.Device != "" {
			dev2key[v.Device] = k
		}
	}
	now := time.Now().Unix()
	curHour := now - now%3600
	lastFull := curHour - 7200 // Netflow schreibt verzögert
	if now-curHour >= 600 {
		lastFull = curHour - 3600
	}
	done, _ := strconv.ParseInt(kvGet("insight_upto", "0"), 10, 64)
	start := max(done-2*3600, lastFull-int64(trafficInsightBackfill-1)*3600)
	imported := 0
	own := arpIntfSnapshot()
	for hour := start; hour <= lastFull; hour += 3600 {
		rows, err := opn.insightTop(hour, hour+3600)
		if err != nil {
			return err
		}
		byIP := devicesByIP(listDevices())
		per := map[int64][2]int64{}
		for _, r := range rows {
			ip := strings.TrimSpace(gs(r, "src_addr"))
			d := byIP[ip]
			if d == nil {
				continue
			}
			intf := pyStr(r["if"])
			idents := map[string]bool{}
			for _, s := range []string{intf, info[intf].Device, dev2key[intf]} {
				if s != "" {
					idents[s] = true
				}
			}
			if o := own[ip]; o != "" && len(idents) > 1 && !idents[o] {
				continue // gleicher Verkehr auf dem anderen VLAN-Interface
			}
			tv, ok := r["total"]
			if !ok {
				tv = r["octets"]
			}
			total := int64(num(tv))
			cur := per[d.ID]
			if pyStr(r["direction"]) == "in" { // ins Firewall-Interface hinein = vom Gerät gesendet
				cur[1] += total
			} else {
				cur[0] += total
			}
			per[d.ID] = cur
		}
		if len(per) > 0 {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			var ids []int64
			for id, v := range per {
				if _, err := tx.Exec("INSERT OR REPLACE INTO traffic_hourly(device, ts, rx, tx, src) VALUES(?,?,?,?,'insight')",
					id, hour, v[0], v[1]); err != nil {
					tx.Rollback()
					return err
				}
				ids = append(ids, id)
			}
			if err := recomputeDailyTx(tx, ids, []int64{dayStart(hour)}); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			imported++
		}
	}
	kvSet("insight_upto", lastFull)
	trMu.Lock()
	if imported > 0 || done > 0 {
		trState.Insight = fmt.Sprintf("aktiv – %d Stunde(n) übernommen", imported)
	} else {
		trState.Insight = "aktiv, aber keine Daten zu bekannten Geräten"
	}
	trState.InsightError = ""
	trState.InsightLast = now
	trMu.Unlock()
	return nil
}

func trafficCleanup() {
	now := time.Now().Unix()
	db.Exec("DELETE FROM traffic_hourly WHERE ts < ?", now-int64(trafficHourlyDays)*86400)
	db.Exec("DELETE FROM traffic_daily WHERE ts < ?", now-int64(trafficDailyDays)*86400)
	db.Exec("DELETE FROM traffic_hourly WHERE device NOT IN (SELECT id FROM devices)")
	db.Exec("DELETE FROM traffic_daily WHERE device NOT IN (SELECT id FROM devices)")
}

func trafficLoop() {
	time.Sleep(8 * time.Second) // erster Scan füllt die ARP-Zuordnung
	var lastInsight, lastClean time.Time
	lastErr := "\x00"
	for {
		t0 := time.Now()
		if err := trafficPoll(); err != nil {
			msg := err.Error()
			var pe *apiPermissionError
			if errors.As(err, &pe) {
				msg += " – ohne dieses Recht gibt es keine Traffic-Daten."
			} else {
				trMu.Lock()
				ifCacheTS = time.Time{} // Interface-Liste beim nächsten Mal neu holen
				trMu.Unlock()
			}
			trMu.Lock()
			trState.Error = msg
			trMu.Unlock()
		}
		st := trafficStatus()
		if st.Error != lastErr {
			lastErr = st.Error
			if lastErr != "" {
				logWarn("Traffic: %s", lastErr)
			} else {
				logInfo("Traffic-Abfrage läuft (%s)", strings.Join(st.Interfaces, ", "))
			}
		}
		if time.Since(lastInsight) > 600*time.Second {
			lastInsight = time.Now()
			if err := insightImport(); err != nil {
				var pe *apiPermissionError
				trMu.Lock()
				if errors.As(err, &pe) {
					trState.Insight = "kein Zugriff"
					trState.InsightError = err.Error() + " – nur für den Verlauf aus Insight nötig, Live-Daten laufen trotzdem."
				} else {
					trState.Insight = "Fehler"
					trState.InsightError = err.Error()
				}
				trMu.Unlock()
				logDebug("Insight: %v", err)
			}
		}
		if time.Since(lastClean) > time.Hour {
			lastClean = time.Now()
			trafficCleanup()
		}
		time.Sleep(max(time.Second, time.Duration(trafficInterval)*time.Second-time.Since(t0)))
	}
}

// ---- Auswertungen ----

func devFilter(device *int64, vlan *int) (string, []any) {
	if device != nil {
		return " AND device = ?", []any{*device}
	}
	if vlan != nil {
		return " AND device IN (SELECT id FROM devices WHERE vlan = ?)", []any{*vlan}
	}
	return "", nil
}

type bucket struct {
	TS int64   `json:"ts"`
	RX float64 `json:"rx"`
	TX float64 `json:"tx"`
}

func trafficSeries(rng string, device *int64, vlan *int) []bucket {
	kind, starts, end := rangeWindow(rng, time.Now().Unix())
	table := "traffic_hourly"
	if kind == "d" {
		table = "traffic_daily"
	}
	where, args := devFilter(device, vlan)
	out := make([]bucket, len(starts))
	for i, t := range starts {
		out[i].TS = t
	}
	rows, err := db.Query("SELECT ts, SUM(rx), SUM(tx) FROM "+table+" WHERE ts >= ? AND ts < ?"+where+" GROUP BY ts",
		append([]any{starts[0], end}, args...)...)
	if err != nil {
		logWarn("Traffic-Verlauf: %v", err)
		return out
	}
	defer rows.Close()
	bounds := append(append([]int64{}, starts...), end)
	for rows.Next() {
		var ts int64
		var rx, tx float64
		if rows.Scan(&ts, &rx, &tx) != nil {
			continue
		}
		for i := range starts {
			if bounds[i] <= ts && ts < bounds[i+1] {
				out[i].RX += rx
				out[i].TX += tx
				break
			}
		}
	}
	return out
}

// trafficTotals: Summen pro Gerät im Zeitraum: device_id -> (rx, tx). rng: today | 24h | 7d | 30d.
func trafficTotals(rng string, device *int64, vlan *int) map[int64][2]float64 {
	now := time.Now().Unix()
	table, since := "traffic_hourly", int64(0)
	switch rng {
	case "today":
		since = dayStart(now)
	case "24h":
		since = now - now%3600 - 23*3600
	case "7d":
		since = dayStart(now - 6*86400)
	default:
		_, days, _ := rangeWindow("30d", now)
		table, since = "traffic_daily", days[0]
	}
	where, args := devFilter(device, vlan)
	out := map[int64][2]float64{}
	rows, err := db.Query("SELECT device, SUM(rx), SUM(tx) FROM "+table+" WHERE ts >= ?"+where+" GROUP BY device",
		append([]any{since}, args...)...)
	if err != nil {
		logWarn("Traffic-Summen: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var rx, tx float64
		if rows.Scan(&id, &rx, &tx) == nil {
			out[id] = [2]float64{rx, tx}
		}
	}
	return out
}

func apiTraffic(q url.Values) map[string]any {
	rng := q.Get("range")
	switch rng {
	case "live", "today", "24h", "7d", "30d":
	default:
		rng = "24h"
	}
	var vlan *int
	if v, err := strconv.Atoi(q.Get("vlan")); err == nil {
		vlan = &v
	}
	devs := map[int64]*Device{}
	for _, d := range listDevices() {
		devs[d.ID] = d
	}
	var vals map[int64][2]float64
	if rng == "live" {
		vals = liveSnapshot()
	} else {
		vals = trafficTotals(rng, nil, vlan)
	}
	type row struct {
		ID     int64   `json:"id"`
		Name   string  `json:"name"`
		Named  bool    `json:"named"`
		IP     string  `json:"ip"`
		VLAN   int     `json:"vlan"`
		Online int     `json:"online"`
		RX     float64 `json:"rx"`
		TX     float64 `json:"tx"`
	}
	rows := []row{}
	perVLAN := map[int]*[3]float64{}
	for id, v := range vals {
		d := devs[id]
		if d == nil || (vlan != nil && d.VLAN != *vlan) || v[0]+v[1] <= 0 {
			continue
		}
		rows = append(rows, row{id, displayName(d), d.Name != "", d.IP, d.VLAN, d.Online, v[0], v[1]})
		pv := perVLAN[d.VLAN]
		if pv == nil {
			pv = &[3]float64{}
			perVLAN[d.VLAN] = pv
		}
		pv[0] += v[0]
		pv[1] += v[1]
		pv[2]++
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if a, b := rows[i].RX+rows[i].TX, rows[j].RX+rows[j].TX; a != b {
			return a > b
		}
		return rows[i].ID < rows[j].ID
	})
	var totRX, totTX float64
	for _, r := range rows {
		totRX += r.RX
		totTX += r.TX
	}
	vlist := []map[string]any{}
	for v, pv := range perVLAN {
		vlist = append(vlist, map[string]any{"id": v, "label": vlanLabel(v), "rx": pv[0], "tx": pv[1], "devices": int(pv[2])})
	}
	sort.Slice(vlist, func(i, j int) bool {
		a := vlist[i]["rx"].(float64) + vlist[i]["tx"].(float64)
		b := vlist[j]["rx"].(float64) + vlist[j]["tx"].(float64)
		if a != b {
			return a > b
		}
		return vlist[i]["id"].(int) < vlist[j]["id"].(int)
	})
	n := len(rows)
	if len(rows) > 100 {
		rows = rows[:100]
	}
	out := map[string]any{
		"range": rng, "devices": rows, "vlans": vlist,
		"total":  map[string]any{"rx": totRX, "tx": totTX, "devices": n},
		"status": trafficStatus(),
	}
	if _, ok := ranges[rng]; ok {
		out["series"] = trafficSeries(rng, nil, vlan)
	}
	return out
}

func apiDeviceTraffic(id int64, q url.Values) map[string]any {
	rng := q.Get("range")
	if _, ok := ranges[rng]; !ok {
		rng = "24h"
	}
	totals := map[string]any{}
	for _, r := range []string{"today", "24h", "7d", "30d"} {
		t := trafficTotals(r, &id, nil)[id]
		totals[r] = map[string]float64{"rx": t[0], "tx": t[1]}
	}
	live := liveSnapshot()[id]
	trMu.Lock()
	var alert any
	if st := alertState[id]; st != nil {
		c := *st
		alert = c
	}
	trMu.Unlock()
	return map[string]any{"range": rng, "series": trafficSeries(rng, &id, nil), "totals": totals,
		"live": map[string]float64{"rx": live[0], "tx": live[1]}, "alert": alert}
}

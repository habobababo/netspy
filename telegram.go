package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// Telegram
// --------------------------------------------------------------------------

type telegramError struct {
	msg        string
	retryAfter int
}

func (e *telegramError) Error() string { return e.msg }

var tgClient = newClient(true, true)

func tgAPI(method string, payload any, timeout time.Duration) (map[string]any, error) {
	u := fmt.Sprintf("https://api.telegram.org/bot%s/%s", tgToken, method)
	res, _, err := doJSON(tgClient, "POST", u, nil, payload, timeout)
	var he *httpError
	var ne *netError
	switch {
	case errors.As(err, &he):
		var body map[string]any
		json.Unmarshal(he.Body, &body)
		desc := gs(body, "description")
		if desc == "" {
			desc = fmt.Sprintf("HTTP %d", he.Code)
		}
		return nil, &telegramError{desc, int(num(asMap(body["parameters"])["retry_after"]))}
	case errors.As(err, &ne):
		return nil, &telegramError{msg: "api.telegram.org nicht erreichbar: " + ne.Error()}
	case err != nil:
		return nil, &telegramError{msg: err.Error()}
	}
	return asMap(res), nil
}

type tgMsg struct {
	text, chat string
	eventID    int64
}

var (
	tgQueue   = make(chan tgMsg, 10000)
	tgStateMu sync.Mutex
	tgLastErr string
	tgLastOK  int64
)

// tgSendNow sendet sofort, mit Wiederholung bei Rate-Limit. Gibt (ok, Fehler) zurück.
func tgSendNow(text, chat string) (bool, string) {
	if chat == "" {
		chat = tgChat
	}
	if tgToken == "" || chat == "" {
		return false, "Telegram nicht konfiguriert (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID fehlen)"
	}
	payload := map[string]any{"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true}
	errMsg := ""
	for attempt := 0; attempt < 5; attempt++ {
		_, err := tgAPI("sendMessage", payload, 15*time.Second)
		if err == nil {
			tgStateMu.Lock()
			tgLastOK, tgLastErr = time.Now().Unix(), ""
			tgStateMu.Unlock()
			return true, ""
		}
		errMsg = err.Error()
		var te *telegramError
		if errors.As(err, &te) && te.retryAfter > 0 { // 429 Too Many Requests
			time.Sleep(time.Duration(te.retryAfter+1) * time.Second)
			continue
		}
		if strings.Contains(errMsg, "can't parse entities") { // Formatierungsproblem -> ohne HTML senden
			delete(payload, "parse_mode")
			continue
		}
		if strings.Contains(errMsg, "nicht erreichbar") && attempt < 4 {
			time.Sleep(time.Duration(5*(attempt+1)) * time.Second)
			continue
		}
		break
	}
	tgStateMu.Lock()
	tgLastErr = errMsg
	tgStateMu.Unlock()
	logWarn("Telegram-Fehler: %s", errMsg)
	return false, errMsg
}

// tgSend legt die Nachricht in die Warteschlange (blockiert den Scan nicht).
func tgSend(text string, eventID int64) bool {
	if tgToken == "" || tgChat == "" {
		setEventTg(eventID, "error: Telegram nicht konfiguriert")
		return false
	}
	tgQueue <- tgMsg{text: text, eventID: eventID}
	return true
}

func tgWorker() {
	for m := range tgQueue {
		ok, err := tgSendNow(m.text, m.chat)
		if ok {
			setEventTg(m.eventID, "sent")
		} else {
			setEventTg(m.eventID, "error: "+err)
		}
		time.Sleep(1100 * time.Millisecond) // Telegram erlaubt ca. 1 Nachricht/Sekunde pro Chat
	}
}

func fmtDevice(d *Device) string {
	name := displayName(d)
	lines := []string{"<b>" + esc(name) + "</b>"}
	if d.Hostname != "" && d.Hostname != name {
		lines = append(lines, "Hostname: "+esc(d.Hostname))
	}
	lines = append(lines, esc(vlanLabel(d.VLAN))+" · "+esc(d.IP))
	l := strings.TrimSpace("<code>" + esc(d.MAC) + "</code> " + esc(d.Vendor))
	if isRandomMAC(d.MAC) {
		l += " · private MAC"
	}
	lines = append(lines, l)
	if d.Conn != "" {
		lines = append(lines, esc(d.Conn))
	}
	return strings.Join(lines, "\n")
}

func fmtNewDevice(d *Device) string {
	var b strings.Builder
	b.WriteString("🆕 <b>Neues Gerät im Netz</b>\n")
	b.WriteString("Name: <b>" + esc(firstNonEmpty(d.UnifiName, d.Hostname, "unbekannt (kein Hostname gemeldet)")) + "</b>\n")
	if d.UnifiName != "" && d.Hostname != "" {
		b.WriteString("Hostname: " + esc(d.Hostname) + "\n")
	}
	if d.Conn != "" {
		b.WriteString("Verbindung: " + esc(d.Conn) + "\n")
	}
	b.WriteString("Hersteller: " + esc(firstNonEmpty(d.Vendor, "-")) + "\n")
	b.WriteString(esc(vlanLabel(d.VLAN)) + " · IP " + esc(d.IP) + "\n")
	b.WriteString("MAC <code>" + esc(d.MAC) + "</code>\n")
	b.WriteString("Interface: " + esc(firstNonEmpty(d.Interface, "-")))
	return b.String()
}

// findDevices: erst exakte Treffer (Name, Hostname, IP, MAC), dann Teiltreffer.
func findDevices(devs []*Device, arg string) []*Device {
	arg = strings.ToLower(arg)
	fields := func(d *Device) []string {
		return []string{strings.ToLower(d.Name), strings.ToLower(d.UnifiName), strings.ToLower(d.Hostname), d.IP, d.MAC}
	}
	var exact, part []*Device
	for _, d := range devs {
		hitExact, hitPart := false, false
		for _, f := range fields(d) {
			if f == arg {
				hitExact = true
			}
			if f != "" && strings.Contains(f, arg) {
				hitPart = true
			}
		}
		if hitExact {
			exact = append(exact, d)
		}
		if hitPart {
			part = append(part, d)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return part
}

// tgBotLoop: einfache Bot-Befehle per Long-Polling.
func tgBotLoop() {
	offset, _ := strconv.ParseInt(kvGet("tg_offset", "0"), 10, 64)
	logInfo("Telegram-Bot-Befehle aktiv")
	cmds := [][2]string{
		{"check", "Onlinestatus eines Geräts (Name/IP/MAC)"},
		{"online", "Alle Geräte online [vlan]"},
		{"offline", "Alle Geräte offline [vlan]"},
		{"status", "Übersicht"},
		{"scan", "Sofort scannen"},
		{"traffic", "Traffic eines Geräts (Name/IP/MAC)"},
		{"top", "Top-Verbraucher [live|24h|7d|30d] [vlan]"},
	}
	var list []map[string]string
	for _, c := range cmds {
		list = append(list, map[string]string{"command": c[0], "description": c[1]})
	}
	if _, err := tgAPI("setMyCommands", map[string]any{"commands": list}, 15*time.Second); err != nil {
		logDebug("setMyCommands: %v", err)
	}
	for {
		res, err := tgAPI("getUpdates", map[string]any{"timeout": 50, "offset": offset}, 60*time.Second)
		if err != nil {
			logDebug("Telegram-Polling: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		for _, upd := range mapsOf(res["result"]) {
			offset = int64(num(upd["update_id"])) + 1
			kvSet("tg_offset", offset)
			msg := asMap(upd["message"])
			chat := pyStr(asMap(msg["chat"])["id"])
			text := strings.TrimSpace(gs(msg, "text"))
			if !strings.HasPrefix(text, "/") || chat != tgChat {
				continue
			}
			tgSendNow(handleCommand(text), chat)
		}
	}
}

func handleCommand(text string) string {
	cmd, arg, _ := strings.Cut(text, " ")
	cmd, _, _ = strings.Cut(cmd, "@")
	cmd = strings.ToLower(cmd)
	arg = strings.ToLower(strings.TrimSpace(arg))
	devs := listDevices()
	switch cmd {
	case "/online", "/offline":
		want := 0
		if cmd == "/online" {
			want = 1
		}
		var sel []*Device
		for _, d := range devs {
			if d.Online == want && (arg == "" || strconv.Itoa(d.VLAN) == arg) {
				sel = append(sel, d)
			}
		}
		if len(sel) == 0 {
			return "Keine Geräte."
		}
		vk := func(v int) int {
			if v == 0 {
				return 999
			}
			return v
		}
		sort.SliceStable(sel, func(i, j int) bool {
			if vk(sel[i].VLAN) != vk(sel[j].VLAN) {
				return vk(sel[i].VLAN) < vk(sel[j].VLAN)
			}
			return ipSortKey(sel[i].IP) < ipSortKey(sel[j].IP)
		})
		var lines []string
		cur := -1
		dot := "🔴"
		if want == 1 {
			dot = "🟢"
		}
		for _, d := range sel {
			if d.VLAN != cur {
				cur = d.VLAN
				lines = append(lines, "\n<b>"+esc(vlanLabel(cur))+"</b>")
			}
			lines = append(lines, fmt.Sprintf("%s %s – %s", dot, esc(displayName(d)), esc(d.IP)))
		}
		title := "Offline"
		if want == 1 {
			title = "Online"
		}
		return fmt.Sprintf("%s (%d):", title, len(sel)) + strings.Join(lines, "\n")
	case "/check", "/status":
		if arg == "" {
			on := 0
			for _, d := range devs {
				on += d.Online
			}
			return fmt.Sprintf("%d von %d Geräten online.\nNutze /check &lt;name|ip|mac&gt;", on, len(devs))
		}
		hits := findDevices(devs, arg)
		if len(hits) == 0 {
			return fmt.Sprintf("Kein Gerät „%s“ gefunden.", esc(arg))
		}
		if len(hits) > 10 {
			hits = hits[:10]
		}
		var live map[int64]bool
		if cmd == "/check" && onlineMode != "arp" {
			// Live-Ping, damit die Antwort aktuell ist und nicht vom letzten Scan stammt
			live = map[int64]bool{}
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 10)
			for _, d := range hits {
				wg.Add(1)
				go func(d *Device) {
					defer wg.Done()
					sem <- struct{}{}
					ok := d.IP != "" && ping(d.IP)
					<-sem
					mu.Lock()
					live[d.ID] = ok
					mu.Unlock()
				}(d)
			}
			wg.Wait()
		}
		var out []string
		for _, d := range hits {
			ts := "-"
			if d.lastSeen() != 0 {
				ts = fmtTime(d.lastSeen(), "02.01. 15:04")
			}
			var status string
			if ok, has := live[d.ID]; has {
				switch {
				case ok:
					status = "🟢 online (antwortet auf Ping)"
				case d.Online == 1:
					status = "🟡 kein Ping, laut Firewall aber noch aktiv"
				default:
					status = "🔴 offline"
				}
			} else if d.Online == 1 {
				status = "🟢 online"
			} else {
				status = "🔴 offline"
			}
			out = append(out, fmt.Sprintf("%s\n%s\nZuletzt gesehen: %s", status, fmtDevice(d), ts))
		}
		return strings.Join(out, "\n\n")
	case "/scan":
		go scanOnce()
		return "Scan gestartet."
	case "/traffic":
		return cmdTraffic(devs, arg)
	case "/top":
		return cmdTop(devs, arg)
	}
	return "Befehle:\n/check NAME – Onlinestatus prüfen (live, auch IP oder MAC)\n" +
		"/online [vlan] – Geräte online\n/offline [vlan] – Geräte offline\n" +
		"/status – Übersicht\n/scan – sofort scannen\n" +
		"/traffic NAME – Traffic eines Geräts\n/top [live|24h|7d|30d] [vlan] – Top-Verbraucher"
}

func trafficProblem() string {
	if !trafficEnabled {
		return "Traffic-Erfassung ist ausgeschaltet (TRAFFIC_ENABLED=false)."
	}
	st := trafficStatus()
	if st.Error != "" {
		return "⚠️ " + esc(st.Error)
	}
	if st.Last == 0 {
		return "Noch keine Traffic-Daten – erste Abfrage läuft."
	}
	return ""
}

func withProblem(prob, s string) string {
	if prob != "" {
		return prob + "\n\n" + s
	}
	return s
}

func cmdTraffic(devs []*Device, arg string) string {
	prob := trafficProblem()
	live := liveSnapshot()
	if arg == "" {
		var sum, rx24, tx24 float64
		for _, r := range live {
			sum += r[0] + r[1]
		}
		for _, v := range trafficTotals("24h", nil, nil) {
			rx24 += v[0]
			tx24 += v[1]
		}
		return withProblem(prob, fmt.Sprintf("📊 <b>Traffic gesamt</b>\nLive: %s (%d aktive Geräte)\n"+
			"24 h: ↓ %s · ↑ %s\n\nNutze /traffic &lt;name|ip|mac&gt; oder /top", fmtRate(sum), len(live), fmtBytes(rx24), fmtBytes(tx24)))
	}
	hits := findDevices(devs, arg)
	if len(hits) == 0 {
		return fmt.Sprintf("Kein Gerät „%s“ gefunden.", esc(arg))
	}
	var out []string
	for i, d := range hits {
		if i >= 5 {
			break
		}
		r := live[d.ID]
		lines := []string{"📊 <b>" + esc(displayName(d)) + "</b>", esc(vlanLabel(d.VLAN)) + " · " + esc(d.IP),
			fmt.Sprintf("Live: ↓ %s · ↑ %s", fmtRate(r[0]), fmtRate(r[1]))}
		for _, rl := range [][2]string{{"today", "Heute"}, {"24h", "24 h"}, {"7d", "7 Tage"}, {"30d", "30 Tage"}} {
			id := d.ID
			t := trafficTotals(rl[0], &id, nil)[d.ID]
			lines = append(lines, fmt.Sprintf("%s: ↓ %s · ↑ %s", rl[1], fmtBytes(t[0]), fmtBytes(t[1])))
		}
		if alertActive(d.ID) {
			lines = append(lines, "⚠️ Traffic-Alarm aktiv")
		}
		out = append(out, strings.Join(lines, "\n"))
	}
	if len(hits) > 5 {
		out = append(out, fmt.Sprintf("… und %d weitere Treffer", len(hits)-5))
	}
	return withProblem(prob, strings.Join(out, "\n\n"))
}

func cmdTop(devs []*Device, arg string) string {
	rng := ""
	var vlan *int
	for _, a := range strings.Fields(arg) {
		a = strings.ReplaceAll(strings.ReplaceAll(a, "tage", "d"), "h24", "24h")
		switch a {
		case "live", "24h", "7d", "30d":
			rng = a
		case "heute", "today":
			rng = "today"
		default:
			if n, err := strconv.Atoi(a); err == nil && n >= 0 && isDigits(a) {
				vlan = &n
			}
		}
	}
	byID := map[int64]*Device{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	labels := map[string]string{"live": "jetzt", "today": "heute", "24h": "letzte 24 h", "7d": "letzte 7 Tage", "30d": "letzte 30 Tage"}

	block := func(r string, n int) string {
		var vals map[int64][2]float64
		if r == "live" {
			vals = liveSnapshot()
		} else {
			vals = trafficTotals(r, nil, vlan)
		}
		type row struct {
			d      *Device
			rx, tx float64
		}
		var rows []row
		for id, v := range vals {
			d := byID[id]
			if d == nil || (vlan != nil && d.VLAN != *vlan) || v[0]+v[1] <= 0 {
				continue
			}
			rows = append(rows, row{d, v[0], v[1]})
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if a, b := rows[i].rx+rows[i].tx, rows[j].rx+rows[j].tx; a != b {
				return a > b
			}
			return rows[i].d.ID < rows[j].d.ID
		})
		f := fmtBytes
		if r == "live" {
			f = fmtRate
		}
		head := "<b>Top " + labels[r] + "</b>"
		if vlan != nil {
			head += " · " + esc(vlanLabel(*vlan))
		}
		if len(rows) == 0 {
			return head + "\nkeine Daten"
		}
		lines := []string{head}
		for i, x := range rows {
			if i >= n {
				break
			}
			lines = append(lines, fmt.Sprintf("%d. %s – ↓ %s · ↑ %s", i+1, esc(displayName(x.d)), f(x.rx), f(x.tx)))
		}
		if r != "live" && vlan == nil {
			per := map[int]float64{}
			for _, x := range rows {
				per[x.d.VLAN] += x.rx + x.tx
			}
			type pv struct {
				v int
				t float64
			}
			var pvs []pv
			for v, t := range per {
				pvs = append(pvs, pv{v, t})
			}
			sort.Slice(pvs, func(i, j int) bool {
				if pvs[i].t != pvs[j].t {
					return pvs[i].t > pvs[j].t
				}
				return pvs[i].v < pvs[j].v
			})
			var parts []string
			for i, p := range pvs {
				if i >= 6 {
					break
				}
				short, _, _ := strings.Cut(vlanLabel(p.v), " · ")
				parts = append(parts, esc(short)+" "+fmtBytes(p.t))
			}
			lines = append(lines, "<i>Pro VLAN:</i> "+strings.Join(parts, " · "))
		}
		return strings.Join(lines, "\n")
	}

	var parts []string
	if rng != "" {
		parts = []string{block(rng, 10)}
	} else {
		parts = []string{block("live", 5), block("24h", 10)}
	}
	return withProblem(trafficProblem(), strings.Join(parts, "\n\n"))
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

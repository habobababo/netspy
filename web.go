package main

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// --------------------------------------------------------------------------
// Web-Server
// --------------------------------------------------------------------------

//go:embed app/index.html
var indexHTML []byte

func serveWeb() error {
	srv := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", webPort), Handler: http.HandlerFunc(handle)}
	return srv.ListenAndServe()
}

func sendJSON(w http.ResponseWriter, code int, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		code, b = 500, []byte(`{"error":"json"}`)
	}
	send(w, code, b, "application/json")
}

func send(w http.ResponseWriter, code int, b []byte, ctype string) {
	w.Header().Set("Content-Type", ctype+"; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Server", "NetWatch")
	w.WriteHeader(code)
	w.Write(b)
}

func authOK(w http.ResponseWriter, r *http.Request) bool {
	if webPassword == "" {
		return true
	}
	u, p, ok := r.BasicAuth()
	if ok && subtle.ConstantTimeCompare([]byte(u), []byte(webUser)) == 1 &&
		subtle.ConstantTimeCompare([]byte(p), []byte(webPassword)) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="NetWatch"`)
	w.WriteHeader(401)
	return false
}

func readBody(r *http.Request) any {
	b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil || len(b) == 0 {
		return map[string]any{}
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return map[string]any{}
	}
	return v
}

// devID liest die Geräte-ID aus /api/devices/<id>[/…].
func devID(path string) (int64, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 {
		return 0, false
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	return id, err == nil
}

func handle(w http.ResponseWriter, r *http.Request) {
	if !authOK(w, r) {
		return
	}
	logDebug("%s - %s %s", r.RemoteAddr, r.Method, r.URL.RequestURI())
	path := r.URL.Path
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		switch {
		case path == "/" || path == "/index.html":
			send(w, 200, indexHTML, "text/html")
		case path == "/api/state":
			sendJSON(w, 200, apiState())
		case path == "/api/events":
			sendJSON(w, 200, apiEvents(r))
		case path == "/api/traffic":
			sendJSON(w, 200, apiTraffic(r.URL.Query()))
		case strings.HasPrefix(path, "/api/devices/") && strings.HasSuffix(path, "/traffic"):
			id, ok := devID(path)
			if !ok {
				sendJSON(w, 400, map[string]string{"error": "bad id"})
				return
			}
			sendJSON(w, 200, apiDeviceTraffic(id, r.URL.Query()))
		case path == "/api/netmap":
			sendJSON(w, 200, buildNetmap())
		case path == "/health":
			sendJSON(w, 200, map[string]bool{"ok": true})
		default:
			sendJSON(w, 404, map[string]string{"error": "not found"})
		}
	case http.MethodPost:
		switch {
		case path == "/api/scan":
			go scanOnce()
			sendJSON(w, 200, map[string]bool{"ok": true})
		case path == "/api/telegram/test":
			ok, err := tgSendNow("✅ NetWatch Test-Nachricht – Telegram funktioniert.", "")
			res, tg := "erfolgreich", "sent"
			if !ok {
				res, tg = "fehlgeschlagen", "error: "+err
			}
			addEvent(nil, "info", "Telegram-Test "+res, tg)
			code := 200
			if !ok {
				code = 500
			}
			sendJSON(w, code, map[string]any{"ok": ok, "error": err})
		case path == "/api/netmap":
			if err := netmapSave(readBody(r)); err != nil {
				sendJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			sendJSON(w, 200, map[string]bool{"ok": true})
		case strings.HasPrefix(path, "/api/devices/"):
			updateDevice(w, r, path)
		default:
			sendJSON(w, 404, map[string]string{"error": "not found"})
		}
	case http.MethodDelete:
		switch {
		case path == "/api/events":
			db.Exec("DELETE FROM events")
			sendJSON(w, 200, map[string]bool{"ok": true})
		case strings.HasPrefix(path, "/api/devices/"):
			id, err := strconv.ParseInt(path[strings.LastIndex(path, "/")+1:], 10, 64)
			if err != nil {
				sendJSON(w, 400, map[string]string{"error": "bad id"})
				return
			}
			tx, err := db.Begin()
			if err == nil {
				tx.Exec("DELETE FROM devices WHERE id=?", id)
				tx.Exec("DELETE FROM traffic_hourly WHERE device=?", id)
				tx.Exec("DELETE FROM traffic_daily WHERE device=?", id)
				tx.Commit()
			}
			forgetDevice(id)
			sendJSON(w, 200, map[string]bool{"ok": true})
		default:
			sendJSON(w, 404, map[string]string{"error": "not found"})
		}
	default:
		sendJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

func updateDevice(w http.ResponseWriter, r *http.Request, path string) {
	if strings.HasSuffix(path, "/check") {
		id, ok := devID(path)
		if !ok {
			sendJSON(w, 400, map[string]string{"error": "bad id"})
			return
		}
		var ip string
		db.QueryRow("SELECT COALESCE(ip,'') FROM devices WHERE id=?", id).Scan(&ip)
		if ip == "" {
			sendJSON(w, 404, map[string]string{"error": "not found"})
			return
		}
		sendJSON(w, 200, map[string]any{"ok": true, "alive": ping(ip), "ip": ip})
		return
	}
	id, err := strconv.ParseInt(path[strings.LastIndex(path, "/")+1:], 10, 64)
	if err != nil {
		sendJSON(w, 400, map[string]string{"error": "bad id"})
		return
	}
	data := asMap(readBody(r))
	var sets []string
	var args []any
	if v, ok := data["name"]; ok {
		sets, args = append(sets, "name=?"), append(args, strings.TrimSpace(truncRunes(pyStr(v), 80)))
	}
	if v, ok := data["watch"]; ok {
		watch := 0
		if truthy(v) {
			watch = 1
		}
		sets, args = append(sets, "watch=?"), append(args, watch)
	}
	if v, ok := data["traffic_limit"]; ok { // MB/s; null/"" = Standard, 0 = aus
		if v == nil || strings.TrimSpace(pyStr(v)) == "" {
			sets, args = append(sets, "traffic_limit=?"), append(args, nil)
		} else {
			f, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(pyStr(v)), ",", "."), 64)
			if err != nil {
				sendJSON(w, 400, map[string]string{"error": "traffic_limit muss eine Zahl sein"})
				return
			}
			if f < 0 {
				f = 0
			}
			sets, args = append(sets, "traffic_limit=?"), append(args, f)
		}
	}
	if len(sets) == 0 {
		sendJSON(w, 400, map[string]string{"error": "nothing to update"})
		return
	}
	db.Exec("UPDATE devices SET "+strings.Join(sets, ",")+" WHERE id=?", append(args, id)...)
	sendJSON(w, 200, map[string]bool{"ok": true})
}

func apiEvents(r *http.Request) map[string]any {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		limit = 300
	}
	limit = max(1, min(limit, eventKeep))
	q := "SELECT e.*, d.name, d.unifi_name, d.hostname, d.ip, d.mac, d.vlan FROM events e " +
		"LEFT JOIN devices d ON d.id = e.device"
	var args []any
	if kind := r.URL.Query().Get("kind"); kind != "" {
		q += " WHERE e.kind = ?"
		args = append(args, kind)
	}
	q += " ORDER BY e.id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := queryMaps(q, args...)
	if err != nil {
		logWarn("Ereignisse lesen: %v", err)
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	var total int64
	db.QueryRow("SELECT COUNT(*) FROM events").Scan(&total)
	return map[string]any{"events": rows, "total": total}
}

type stateDevice struct {
	*Device
	RxBps        float64 `json:"rx_bps"`
	TxBps        float64 `json:"tx_bps"`
	TrafficAlert bool    `json:"traffic_alert"`
}

func apiState() map[string]any {
	devs := listDevices()
	sort.SliceStable(devs, func(i, j int) bool { return ipSortKey(devs[i].IP) < ipSortKey(devs[j].IP) })
	live := liveSnapshot()
	out := make([]stateDevice, len(devs))
	for i, d := range devs {
		r := live[d.ID]
		out[i] = stateDevice{d, r[0], r[1], alertActive(d.ID)}
	}
	vl := []map[string]any{}
	for _, v := range append(append([]int{}, vlans...), 0) {
		total, on := 0, 0
		for _, d := range devs {
			if d.VLAN == v {
				total++
				on += d.Online
			}
		}
		if v == 0 && total == 0 {
			continue
		}
		subnet := ""
		if v != 0 {
			subnet = fmt.Sprintf("%s.%d.0/24", subnetPrefix, v)
		}
		vl = append(vl, map[string]any{"id": v, "label": vlanLabel(v), "subnet": subnet, "total": total, "online": on})
	}
	ls, le, dur, ue := scanState()
	tgStateMu.Lock()
	tgErr, tgOK := tgLastErr, tgLastOK
	tgStateMu.Unlock()
	return map[string]any{
		"devices": out, "vlans": vl,
		"tg_error": tgErr, "tg_last_ok": tgOK, "notify_new": notifyNew,
		"last_scan": ls, "last_error": le, "duration": dur, "interval": scanInterval,
		"telegram": tgToken != "" && tgChat != "", "mode": onlineMode,
		"unifi": unifi.enabled(), "unifi_error": ue, "unifi_names": unifiUseNames,
		"traffic": trafficStatus(),
	}
}

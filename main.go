// NetWatch – kleiner NetAlertX-Ersatz für OPNsense.
//
//   - Holt ARP-Tabelle + DHCP-Leases über die OPNsense-API
//   - Ordnet Geräte nach VLAN (192.168.<VLAN>.x)
//   - Web-UI zum Benennen / Beobachten von Geräten
//   - Online-Prüfung (Ping + ARP)
//   - Telegram-Benachrichtigungen + Bot-Befehle (/online, /offline, /status <name>)
//   - Traffic pro Gerät (OPNsense Top Talker, optional Insight/Netflow) mit Verlauf + Alarm
//   - Netzplan (Reiter „Netz“) aus erkannten Geräten, UniFi-Uplinks und eigenen Ergänzungen
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // Zeitzonen ohne tzdata-Paket im Image
)

// --------------------------------------------------------------------------
// Konfiguration
// --------------------------------------------------------------------------

func env(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on", "ja":
		return true
	}
	return false
}

func envInt(key string, def int) int {
	n, err := strconv.Atoi(env(key, ""))
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	f, err := strconv.ParseFloat(strings.ReplaceAll(env(key, ""), ",", "."), 64)
	if err != nil {
		return def
	}
	return f
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

var (
	opnURL       = strings.TrimRight(env("OPNSENSE_URL", "https://192.168.10.1"), "/")
	opnKey       = env("OPNSENSE_KEY", "")
	opnSecret    = env("OPNSENSE_SECRET", "")
	opnVerifySSL = envBool("OPNSENSE_VERIFY_SSL", false)

	subnetPrefix = env("SUBNET_PREFIX", "192.168")
	vlans        = parseVLANs(env("VLANS", "10,20,30,40,50,60,70,80,90"))
	vlanNames    = parseVLANNames(env("VLAN_NAMES", ""))

	scanInterval    = envInt("SCAN_INTERVAL", 60)
	offlineAfter    = envInt("OFFLINE_AFTER_CHECKS", 3) // so viele Fehlversuche bis "offline"
	onlineMode      = env("ONLINE_MODE", "ping_or_arp") // ping_or_arp | ping | arp
	pingTimeout     = envInt("PING_TIMEOUT", 1)
	pingWorkers     = envInt("PING_WORKERS", 64)
	includeFirewall = envBool("INCLUDE_FIREWALL", false) // eigene Interfaces der OPNsense anzeigen

	tgToken         = env("TELEGRAM_BOT_TOKEN", "")
	tgChat          = env("TELEGRAM_CHAT_ID", "")
	tgCommands      = envBool("TELEGRAM_COMMANDS", true)
	notifyNew       = envBool("NOTIFY_NEW_DEVICES", true)
	watchDefault    = envBool("WATCH_NEW_DEVICES", false) // neue Geräte automatisch beobachten?
	mergeRandomMAC  = envBool("MERGE_RANDOM_MAC", true)   // private MAC + gleicher Hostname = gleiches Gerät
	notifyRandomMAC = envBool("NOTIFY_RANDOM_MAC", true)  // Meldung auch für unbekannte Geräte mit privater MAC

	unifiURL       = strings.TrimRight(env("UNIFI_URL", ""), "/") // leer = UniFi deaktiviert
	unifiUser      = env("UNIFI_USER", "")
	unifiPassword  = env("UNIFI_PASSWORD", "")
	unifiSite      = env("UNIFI_SITE", "default")
	unifiIsOS      = envBool("UNIFI_IS_UNIFI_OS", true) // UDM / Cloud Key Gen2 / UniFi OS Server
	unifiVerifySSL = envBool("UNIFI_VERIFY_SSL", false)
	unifiUseNames  = envBool("UNIFI_USE_NAMES", true) // Aliasnamen aus UniFi übernehmen

	trafficEnabled         = envBool("TRAFFIC_ENABLED", true)
	trafficInterval        = max(10, envInt("TRAFFIC_INTERVAL", 30))  // Sekunden zwischen Top-Talker-Abfragen
	trafficInterfaces      = splitList(env("TRAFFIC_INTERFACES", "")) // leer = automatisch
	trafficSwap            = envBool("TRAFFIC_SWAP_DIRECTION", false) // ↑/↓ vertauscht? -> true
	trafficInsight         = strings.ToLower(env("TRAFFIC_INSIGHT", "auto"))
	trafficInsightBackfill = envInt("TRAFFIC_INSIGHT_BACKFILL_HOURS", 24)
	trafficHourlyDays      = max(8, envInt("TRAFFIC_HOURLY_DAYS", 31)) // min. 8 für die 7-Tage-Grafik
	trafficDailyDays       = max(31, envInt("TRAFFIC_DAILY_DAYS", 365))
	trafficAlertMBs        = envFloat("TRAFFIC_ALERT_MBS", 0) // MB/s, 0 = kein Alarm
	trafficAlertMinutes    = max(1, envInt("TRAFFIC_ALERT_MINUTES", 10))
	trafficAlertDirection  = strings.ToLower(env("TRAFFIC_ALERT_DIRECTION", "total")) // total | down | up

	webPort     = envInt("WEB_PORT", 8080)
	webUser     = env("WEB_USER", "admin")
	webPassword = env("WEB_PASSWORD", "")
	dbPath      = env("DB_PATH", "/data/netwatch.db")
)

func parseVLANs(s string) []int {
	var out []int
	for _, x := range splitList(s) {
		if n, err := strconv.Atoi(x); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func parseVLANNames(s string) map[int]string {
	out := map[int]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(k)); err == nil {
			out[n] = strings.TrimSpace(v)
		}
	}
	return out
}

// --------------------------------------------------------------------------
// Logging
// --------------------------------------------------------------------------

var logLevel = map[string]int{"DEBUG": 10, "INFO": 20, "WARNING": 30, "WARN": 30, "ERROR": 40}[strings.ToUpper(env("LOG_LEVEL", "INFO"))]

func logAt(level int, name, format string, args ...any) {
	lv := logLevel
	if lv == 0 {
		lv = 20
	}
	if level < lv {
		return
	}
	log.Printf("%s %s", name, fmt.Sprintf(format, args...))
}

func logDebug(f string, a ...any) { logAt(10, "DEBUG", f, a...) }
func logInfo(f string, a ...any)  { logAt(20, "INFO", f, a...) }
func logWarn(f string, a ...any)  { logAt(30, "WARNING", f, a...) }
func logError(f string, a ...any) { logAt(40, "ERROR", f, a...) }

// --------------------------------------------------------------------------
// Start
// --------------------------------------------------------------------------

func main() {
	log.SetFlags(0)
	log.SetOutput(logWriter{})
	if err := openDB(); err != nil {
		logError("Datenbank %s: %v", dbPath, err)
		os.Exit(1)
	}
	if opnKey == "" || opnSecret == "" {
		logWarn("OPNSENSE_KEY / OPNSENSE_SECRET fehlen – Scans werden fehlschlagen.")
	}
	go tgWorker()
	if tgToken != "" && tgChat != "" {
		logInfo("Telegram aktiv (Chat %s, neue Geräte melden: %s)", tgChat, pyBool(notifyNew))
	} else {
		logWarn("Telegram NICHT konfiguriert – TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID fehlen")
	}
	go scannerLoop()
	if tgToken != "" && tgChat != "" && tgCommands {
		go tgBotLoop()
	}
	if trafficEnabled {
		go trafficLoop()
		alarm := "aus"
		if trafficAlertMBs > 0 {
			alarm = fmt.Sprintf("> %s MB/s für %d min", strconv.FormatFloat(trafficAlertMBs, 'g', -1, 64), trafficAlertMinutes)
		}
		logInfo("Traffic-Erfassung aktiv (alle %d s, Insight: %s, Alarm: %s)", trafficInterval, trafficInsight, alarm)
	}
	ids := make([]string, len(vlans))
	for i, v := range vlans {
		ids[i] = strconv.Itoa(v)
	}
	logInfo("NetWatch läuft auf Port %d (VLANs: %s)", webPort, strings.Join(ids, ","))
	if err := serveWeb(); err != nil {
		logError("Web-Server: %v", err)
		os.Exit(1)
	}
}

// logWriter setzt den Zeitstempel im gleichen Format wie früher (2026-11-13 21:31:13,400).
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	t := time.Now()
	return fmt.Fprintf(os.Stderr, "%s,%03d %s", t.Format("2006-01-02 15:04:05"), t.Nanosecond()/1e6, p)
}

func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

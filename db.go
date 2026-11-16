package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver" // reines Go, kein CGO
	_ "github.com/ncruces/go-sqlite3/embed"
)

// --------------------------------------------------------------------------
// Datenbank (gleiches Schema wie die frühere Python-Version – bestehende DBs laufen weiter)
// --------------------------------------------------------------------------

var db *sql.DB

var schema = []string{
	`CREATE TABLE IF NOT EXISTS devices (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		mac         TEXT NOT NULL,
		vlan        INTEGER NOT NULL,
		ip          TEXT,
		name        TEXT DEFAULT '',
		hostname    TEXT DEFAULT '',
		vendor      TEXT DEFAULT '',
		interface   TEXT DEFAULT '',
		first_seen  INTEGER,
		last_seen   INTEGER,
		online      INTEGER DEFAULT 0,
		fails       INTEGER DEFAULT 0,
		watch       INTEGER DEFAULT 0,
		changed_at  INTEGER,
		UNIQUE(mac, vlan)
	)`,
	`CREATE TABLE IF NOT EXISTS events (
		id     INTEGER PRIMARY KEY AUTOINCREMENT,
		ts     INTEGER,
		device INTEGER,
		kind   TEXT,
		text   TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)`,
	// rx = Download (zum Gerät), tx = Upload (vom Gerät), Bytes
	`CREATE TABLE IF NOT EXISTS traffic_hourly (
		device INTEGER NOT NULL,
		ts     INTEGER NOT NULL,
		rx     INTEGER DEFAULT 0,
		tx     INTEGER DEFAULT 0,
		src    TEXT DEFAULT 'live',
		PRIMARY KEY (device, ts)
	)`,
	`CREATE TABLE IF NOT EXISTS traffic_daily (
		device INTEGER NOT NULL,
		ts     INTEGER NOT NULL,
		rx     INTEGER DEFAULT 0,
		tx     INTEGER DEFAULT 0,
		PRIMARY KEY (device, ts)
	)`,
	`CREATE INDEX IF NOT EXISTS traffic_hourly_ts ON traffic_hourly(ts)`,
	`CREATE INDEX IF NOT EXISTS traffic_daily_ts ON traffic_daily(ts)`,
}

func openDB() error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return err
	}
	d, err := sql.Open("sqlite3", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	d.SetMaxOpenConns(1) // eine Verbindung: Schreibzugriffe laufen nacheinander
	for _, s := range schema {
		if _, err := d.Exec(s); err != nil {
			return fmt.Errorf("Schema: %w", err)
		}
	}
	cols, err := tableCols(d, "devices")
	if err != nil {
		return err
	}
	for _, c := range []string{"unifi_name", "conn"} {
		if !cols[c] {
			if _, err := d.Exec("ALTER TABLE devices ADD COLUMN " + c + " TEXT DEFAULT ''"); err != nil {
				return err
			}
		}
	}
	if !cols["traffic_limit"] { // MB/s, NULL = Standard (TRAFFIC_ALERT_MBS), 0 = aus
		if _, err := d.Exec("ALTER TABLE devices ADD COLUMN traffic_limit REAL DEFAULT NULL"); err != nil {
			return err
		}
	}
	ecols, err := tableCols(d, "events")
	if err != nil {
		return err
	}
	if !ecols["tg"] {
		if _, err := d.Exec("ALTER TABLE events ADD COLUMN tg TEXT DEFAULT ''"); err != nil {
			return err
		}
	}
	db = d
	return nil
}

func tableCols(d *sql.DB, table string) (map[string]bool, error) {
	rows, err := d.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

func kvGet(k, def string) string {
	var v sql.NullString
	if err := db.QueryRow("SELECT v FROM kv WHERE k=?", k).Scan(&v); err != nil || !v.Valid {
		return def
	}
	return v.String
}

func kvSet(k string, v any) {
	if _, err := db.Exec("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", k, fmt.Sprint(v)); err != nil {
		logWarn("kv %s: %v", k, err)
	}
}

const eventKeep = 5000

// addEvent speichert ein Ereignis. tg: "" = keine Telegram-Nachricht, "queued" / "sent" / "error: …"
func addEvent(device *int64, kind, text, tg string) int64 {
	res, err := db.Exec("INSERT INTO events(ts,device,kind,text,tg) VALUES(?,?,?,?,?)",
		time.Now().Unix(), nullID(device), kind, text, tg)
	if err != nil {
		logWarn("Ereignis speichern: %v", err)
		return 0
	}
	db.Exec(fmt.Sprintf("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT %d)", eventKeep))
	id, _ := res.LastInsertId()
	return id
}

func setEventTg(eventID int64, tg string) {
	if eventID == 0 {
		return
	}
	db.Exec("UPDATE events SET tg=? WHERE id=?", tg, eventID)
}

func nullID(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// --------------------------------------------------------------------------
// Geräte
// --------------------------------------------------------------------------

type Device struct {
	ID           int64    `json:"id"`
	MAC          string   `json:"mac"`
	VLAN         int      `json:"vlan"`
	IP           string   `json:"ip"`
	Name         string   `json:"name"`
	Hostname     string   `json:"hostname"`
	Vendor       string   `json:"vendor"`
	Interface    string   `json:"interface"`
	FirstSeen    *int64   `json:"first_seen"`
	LastSeen     *int64   `json:"last_seen"`
	Online       int      `json:"online"`
	Fails        int      `json:"fails"`
	Watch        int      `json:"watch"`
	ChangedAt    *int64   `json:"changed_at"`
	UnifiName    string   `json:"unifi_name"`
	Conn         string   `json:"conn"`
	TrafficLimit *float64 `json:"traffic_limit"`
}

func (d *Device) lastSeen() int64 {
	if d.LastSeen == nil {
		return 0
	}
	return *d.LastSeen
}

const devCols = `id, mac, vlan, COALESCE(ip,''), COALESCE(name,''), COALESCE(hostname,''), COALESCE(vendor,''),
	COALESCE(interface,''), first_seen, last_seen, COALESCE(online,0), COALESCE(fails,0), COALESCE(watch,0),
	changed_at, COALESCE(unifi_name,''), COALESCE(conn,''), traffic_limit`

type scanner interface{ Scan(dest ...any) error }

func scanDevice(r scanner) (*Device, error) {
	var d Device
	var fs, ls, ch sql.NullInt64
	var lim sql.NullFloat64
	if err := r.Scan(&d.ID, &d.MAC, &d.VLAN, &d.IP, &d.Name, &d.Hostname, &d.Vendor, &d.Interface,
		&fs, &ls, &d.Online, &d.Fails, &d.Watch, &ch, &d.UnifiName, &d.Conn, &lim); err != nil {
		return nil, err
	}
	d.FirstSeen, d.LastSeen, d.ChangedAt = nullInt(fs), nullInt(ls), nullInt(ch)
	if lim.Valid {
		v := lim.Float64
		d.TrafficLimit = &v
	}
	return &d, nil
}

func nullInt(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

func listDevices() []*Device {
	rows, err := db.Query("SELECT " + devCols + " FROM devices ORDER BY id")
	if err != nil {
		logWarn("Geräte lesen: %v", err)
		return nil
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			logWarn("Gerät lesen: %v", err)
			continue
		}
		out = append(out, d)
	}
	return out
}

// queryMaps liefert Zeilen als map (für Antworten mit frei zusammengesetzten Spalten).
func queryMaps(q string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				m[c] = string(b)
			} else {
				m[c] = vals[i]
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func sqlInList(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprint(id)
	}
	return strings.Join(parts, ",")
}

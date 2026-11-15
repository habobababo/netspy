#!/usr/bin/env python3
"""
NetWatch – kleiner NetAlertX-Ersatz für OPNsense.

- Holt ARP-Tabelle + DHCP-Leases über die OPNsense-API
- Ordnet Geräte nach VLAN (192.168.<VLAN>.x)
- Web-UI zum Benennen / Beobachten von Geräten
- Online-Prüfung (Ping + ARP)
- Telegram-Benachrichtigungen + Bot-Befehle (/online, /offline, /status <name>)
- Traffic pro Gerät (OPNsense Top Talker, optional Insight/Netflow) mit Verlauf + Alarm

Nur Python-Standardbibliothek, keine Abhängigkeiten.
"""
import base64
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Konfiguration
# --------------------------------------------------------------------------


def env(key, default=None):
    v = os.environ.get(key)
    return default if v is None or v.strip() == "" else v.strip()


def env_bool(key, default=False):
    v = os.environ.get(key)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "ja")


def env_int(key, default):
    try:
        return int(env(key, default))
    except (TypeError, ValueError):
        return default


def env_float(key, default):
    try:
        return float(str(env(key, default)).replace(",", "."))
    except (TypeError, ValueError):
        return default


OPN_URL = (env("OPNSENSE_URL", "https://192.168.10.1") or "").rstrip("/")
OPN_KEY = env("OPNSENSE_KEY", "")
OPN_SECRET = env("OPNSENSE_SECRET", "")
OPN_VERIFY_SSL = env_bool("OPNSENSE_VERIFY_SSL", False)

SUBNET_PREFIX = env("SUBNET_PREFIX", "192.168")
VLANS = [int(x) for x in env("VLANS", "10,20,30,40,50,60,70,80,90").split(",") if x.strip()]
VLAN_NAMES = {}
for part in env("VLAN_NAMES", "").split(","):
    if ":" in part:
        k, v = part.split(":", 1)
        try:
            VLAN_NAMES[int(k.strip())] = v.strip()
        except ValueError:
            pass

SCAN_INTERVAL = env_int("SCAN_INTERVAL", 60)
OFFLINE_AFTER = env_int("OFFLINE_AFTER_CHECKS", 3)        # so viele Fehlversuche bis "offline"
ONLINE_MODE = env("ONLINE_MODE", "ping_or_arp")            # ping_or_arp | ping | arp
PING_TIMEOUT = env_int("PING_TIMEOUT", 1)
PING_WORKERS = env_int("PING_WORKERS", 64)
INCLUDE_FIREWALL = env_bool("INCLUDE_FIREWALL", False)     # eigene Interfaces der OPNsense anzeigen

TG_TOKEN = env("TELEGRAM_BOT_TOKEN", "")
TG_CHAT = env("TELEGRAM_CHAT_ID", "")
TG_COMMANDS = env_bool("TELEGRAM_COMMANDS", True)
NOTIFY_NEW = env_bool("NOTIFY_NEW_DEVICES", True)
WATCH_DEFAULT = env_bool("WATCH_NEW_DEVICES", False)       # neue Geräte automatisch beobachten?
MERGE_RANDOM_MAC = env_bool("MERGE_RANDOM_MAC", True)      # private MAC + gleicher Hostname = gleiches Gerät
NOTIFY_RANDOM_MAC = env_bool("NOTIFY_RANDOM_MAC", True)    # Meldung auch für unbekannte Geräte mit privater MAC

UNIFI_URL = (env("UNIFI_URL", "") or "").rstrip("/")      # leer = UniFi deaktiviert
UNIFI_USER = env("UNIFI_USER", "")
UNIFI_PASSWORD = env("UNIFI_PASSWORD", "")
UNIFI_SITE = env("UNIFI_SITE", "default")
UNIFI_IS_OS = env_bool("UNIFI_IS_UNIFI_OS", True)           # UDM / Cloud Key Gen2 / UniFi OS Server
UNIFI_VERIFY_SSL = env_bool("UNIFI_VERIFY_SSL", False)
UNIFI_USE_NAMES = env_bool("UNIFI_USE_NAMES", True)         # Aliasnamen aus UniFi übernehmen

TRAFFIC_ENABLED = env_bool("TRAFFIC_ENABLED", True)
TRAFFIC_INTERVAL = max(10, env_int("TRAFFIC_INTERVAL", 30))         # Sekunden zwischen Top-Talker-Abfragen
TRAFFIC_INTERFACES = [x.strip() for x in env("TRAFFIC_INTERFACES", "").split(",") if x.strip()]  # leer = automatisch
TRAFFIC_SWAP = env_bool("TRAFFIC_SWAP_DIRECTION", False)            # ↑/↓ vertauscht? -> true
TRAFFIC_INSIGHT = (env("TRAFFIC_INSIGHT", "auto") or "auto").lower()  # auto | true | false
TRAFFIC_INSIGHT_BACKFILL = env_int("TRAFFIC_INSIGHT_BACKFILL_HOURS", 24)
TRAFFIC_HOURLY_DAYS = max(8, env_int("TRAFFIC_HOURLY_DAYS", 31))     # Stundenwerte aufbewahren (min. 8 für 7-Tage-Grafik)
TRAFFIC_DAILY_DAYS = max(31, env_int("TRAFFIC_DAILY_DAYS", 365))     # Tageswerte aufbewahren
TRAFFIC_ALERT_MBS = env_float("TRAFFIC_ALERT_MBS", 0)               # MB/s, 0 = kein Alarm
TRAFFIC_ALERT_MINUTES = max(1, env_int("TRAFFIC_ALERT_MINUTES", 10))
TRAFFIC_ALERT_DIRECTION = (env("TRAFFIC_ALERT_DIRECTION", "total") or "total").lower()  # total | down | up

WEB_PORT = env_int("WEB_PORT", 8080)
WEB_USER = env("WEB_USER", "admin")
WEB_PASSWORD = env("WEB_PASSWORD", "")
DB_PATH = env("DB_PATH", "/data/netwatch.db")

logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netwatch")

HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# Datenbank
# --------------------------------------------------------------------------

db_lock = threading.RLock()
_db = None


def db():
    global _db
    if _db is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _db = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db.row_factory = sqlite3.Row
        _db.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
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
            );
            CREATE TABLE IF NOT EXISTS events (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     INTEGER,
                device INTEGER,
                kind   TEXT,
                text   TEXT
            );
            CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
            -- rx = Download (zum Gerät), tx = Upload (vom Gerät), Bytes
            CREATE TABLE IF NOT EXISTS traffic_hourly (
                device INTEGER NOT NULL,
                ts     INTEGER NOT NULL,
                rx     INTEGER DEFAULT 0,
                tx     INTEGER DEFAULT 0,
                src    TEXT DEFAULT 'live',
                PRIMARY KEY (device, ts)
            );
            CREATE TABLE IF NOT EXISTS traffic_daily (
                device INTEGER NOT NULL,
                ts     INTEGER NOT NULL,
                rx     INTEGER DEFAULT 0,
                tx     INTEGER DEFAULT 0,
                PRIMARY KEY (device, ts)
            );
            CREATE INDEX IF NOT EXISTS traffic_hourly_ts ON traffic_hourly(ts);
            CREATE INDEX IF NOT EXISTS traffic_daily_ts ON traffic_daily(ts);
            """
        )
        cols = {r["name"] for r in _db.execute("PRAGMA table_info(devices)")}
        for col in ("unifi_name", "conn"):
            if col not in cols:
                _db.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT DEFAULT ''")
        if "traffic_limit" not in cols:   # MB/s, NULL = Standard (TRAFFIC_ALERT_MBS), 0 = aus
            _db.execute("ALTER TABLE devices ADD COLUMN traffic_limit REAL DEFAULT NULL")
        ecols = {r["name"] for r in _db.execute("PRAGMA table_info(events)")}
        if "tg" not in ecols:
            _db.execute("ALTER TABLE events ADD COLUMN tg TEXT DEFAULT ''")
        _db.commit()
    return _db


def kv_get(k, default=None):
    with db_lock:
        r = db().execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def kv_set(k, v):
    with db_lock:
        db().execute("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (k, str(v)))
        db().commit()


EVENT_KEEP = 5000


def add_event(device_id, kind, text, tg=""):
    """tg: '' = keine Telegram-Nachricht, 'queued' / 'sent' / 'error: …'"""
    with db_lock:
        cur = db().execute("INSERT INTO events(ts,device,kind,text,tg) VALUES(?,?,?,?,?)",
                           (int(time.time()), device_id, kind, text, tg))
        db().execute(f"DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT {EVENT_KEEP})")
        db().commit()
        return cur.lastrowid


def set_event_tg(event_id, tg):
    if not event_id:
        return
    with db_lock:
        db().execute("UPDATE events SET tg=? WHERE id=?", (tg, event_id))
        db().commit()


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if len(mac) == 17 else ""


def is_random_mac(mac):
    """Lokal administrierte MAC (2. Hex-Ziffer 2/6/A/E) = private/zufällige Adresse (iOS, Android, Windows)."""
    return len(mac or "") == 17 and mac[1].lower() in "26ae"


def vlan_of(ip):
    """192.168.<vlan>.x -> vlan, sonst 0 (= 'Andere')."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return None
    if addr.is_link_local or addr.is_unspecified or addr.is_multicast or ip.endswith(".255"):
        return None  # 169.254.x.x (kein DHCP), 0.0.0.0 usw. ignorieren
    parts = ip.split(".")
    prefix = SUBNET_PREFIX.split(".")
    if parts[: len(prefix)] != prefix:
        return 0
    try:
        third = int(parts[2])
    except (IndexError, ValueError):
        return 0
    return third if third in VLANS else 0


def vlan_label(v):
    if v == 0:
        return "Andere"
    name = VLAN_NAMES.get(v)
    return f"VLAN {v}" + (f" · {name}" if name else "")


def display_name(d):
    return (d.get("name") or (d.get("unifi_name") if UNIFI_USE_NAMES else "")
            or d.get("hostname") or d.get("ip") or d.get("mac"))


def ip_sort_key(ip):
    try:
        return int(ipaddress.IPv4Address(ip or "0.0.0.0"))
    except Exception:
        return 0


# --------------------------------------------------------------------------
# OPNsense API
# --------------------------------------------------------------------------


class OPNsense:
    def __init__(self):
        self.ctx = ssl.create_default_context()
        if not OPN_VERIFY_SSL:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        token = base64.b64encode(f"{OPN_KEY}:{OPN_SECRET}".encode()).decode()
        self.headers = {"Authorization": "Basic " + token, "Accept": "application/json"}
        self.lease_endpoint = None  # wird beim ersten erfolgreichen Abruf gemerkt

    def _req(self, path, payload=None, timeout=20):
        url = OPN_URL + path
        data = None
        headers = dict(self.headers)
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        # Proxy-Variablen für das lokale Netz ignorieren
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        with opener.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode() or "null")

    def _call(self, path, right, payload=None, timeout=20):
        """Wie _req, aber mit verständlichen Fehlermeldungen (401/403/nicht erreichbar)."""
        try:
            return self._req(path, payload, timeout)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError("401 – API-Key/Secret falsch (OPNSENSE_KEY / OPNSENSE_SECRET prüfen)")
            if e.code == 403:
                raise ApiPermissionError(
                    f"403 – dem API-Benutzer fehlt das Recht {right} "
                    "(OPNsense: System → Zugang → Benutzer → Benutzer bearbeiten → Effektive Rechte)")
            raise
        except urllib.error.URLError as e:
            raise RuntimeError(f"OPNsense nicht erreichbar unter {OPN_URL}: {e.reason}")

    # ---- Traffic (Reporting → Traffic) ----
    RIGHT_TRAFFIC = "„Reporting: Traffic“ (ältere Versionen: „Diagnostics: Traffic Graph“)"
    RIGHT_INSIGHT = "„Reporting: Insight“ (ältere Versionen: „Diagnostics: Network Insight“)"

    def traffic_interfaces(self):
        """Interface-Schlüssel (lan, opt1 …) -> {name, device}."""
        res = self._call("/api/diagnostics/traffic/interface", self.RIGHT_TRAFFIC)
        if isinstance(res, dict) and isinstance(res.get("interfaces"), dict):
            res = res["interfaces"]
        out = {}
        for k, v in (res or {}).items() if isinstance(res, dict) else []:
            if isinstance(v, dict):
                out[k] = {"name": v.get("name") or k, "device": v.get("device") or v.get("if") or ""}
        return out

    def traffic_top(self, keys):
        """Top Talker der Interfaces (iftop auf der Firewall, dauert ein paar Sekunden)."""
        path = "/api/diagnostics/traffic/top/" + urllib.parse.quote(",".join(keys), safe=",")
        res = self._call(path, self.RIGHT_TRAFFIC, timeout=90)
        return res if isinstance(res, dict) else {}

    # ---- Insight / Netflow (optional) ----
    def netflow_enabled(self):
        """True/False, None = unbekannt (fehlendes Recht oder alte Version)."""
        try:
            res = self._req("/api/diagnostics/netflow/isEnabled")
        except Exception:
            return None
        if not isinstance(res, dict):
            return None
        return str(res.get("local", res.get("netflow", ""))).lower() in ("1", "true")

    def insight_top(self, frm, to, max_hits=2000):
        """Summen pro Quell-Adresse, Interface und Richtung im Zeitraum (Bytes)."""
        path = (f"/api/diagnostics/networkinsight/top/FlowSourceAddrTotals/{int(frm)}/{int(to)}"
                f"/if,src_addr,direction/octets/{max_hits}")
        res = self._call(path, self.RIGHT_INSIGHT, timeout=60)
        return res if isinstance(res, list) else []

    def arp(self):
        """Liste von dicts mit mac, ip, intf, manufacturer, hostname, expired, permanent."""
        try:
            return self._arp()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError("401 – API-Key/Secret falsch (OPNSENSE_KEY / OPNSENSE_SECRET prüfen)")
            if e.code == 403:
                raise RuntimeError("403 – API-Benutzer fehlt das Recht 'Diagnostics: ARP Table' "
                                   "(System > Zugang > Benutzer > Effektive Rechte)")
            raise
        except urllib.error.URLError as e:
            raise RuntimeError(f"OPNsense nicht erreichbar unter {OPN_URL}: {e.reason}")

    def _arp(self):
        try:
            res = self._req("/api/diagnostics/interface/getArp")
            if isinstance(res, list):
                return res
            if isinstance(res, dict) and isinstance(res.get("rows"), list):
                return res["rows"]
        except urllib.error.HTTPError as e:
            if e.code not in (404, 400):
                raise
        # neuere Versionen: search_arp
        res = self._req("/api/diagnostics/interface/search_arp", {"current": 1, "rowCount": -1})
        return res.get("rows", []) if isinstance(res, dict) else []

    def leases(self):
        """DHCP-Leases (ISC, Kea oder Dnsmasq) -> Liste von dicts (mac, ip, hostname)."""
        candidates = [
            ("/api/dnsmasq/leases/search", "dnsmasq"),
            ("/api/kea/leases4/search", "kea"),
            ("/api/dhcpv4/leases/searchLease", "isc"),
        ]
        if self.lease_endpoint:
            candidates.sort(key=lambda c: c[0] != self.lease_endpoint)
        out = []
        for path, kind in candidates:
            try:
                res = self._req(path, {"current": 1, "rowCount": -1, "searchPhrase": ""})
            except Exception:
                continue
            rows = res.get("rows") if isinstance(res, dict) else None
            if not rows:
                continue
            self.lease_endpoint = path
            for r in rows:
                mac = norm_mac(r.get("mac") or r.get("hwaddr") or r.get("hw_address"))
                ip = r.get("address") or r.get("ip") or r.get("ip_address") or ""
                host = r.get("hostname") or r.get("client-hostname") or r.get("client_hostname") or ""
                if mac and ip:
                    out.append({"mac": mac, "ip": ip, "hostname": host})
            break
        return out


class ApiPermissionError(RuntimeError):
    pass


opn = OPNsense()

# --------------------------------------------------------------------------
# UniFi (optional)
# --------------------------------------------------------------------------


class UniFi:
    """Liest verbundene Clients aus dem UniFi Network Controller (UniFi OS oder klassisch)."""

    def __init__(self):
        self.ctx = ssl.create_default_context()
        if not UNIFI_VERIFY_SSL:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.cookies = {}
        self.csrf = ""
        self.base = UNIFI_URL + ("/proxy/network" if UNIFI_IS_OS else "")
        self.ap_names = {}
        self.ap_names_ts = 0
        self.dev_list = []    # stat/device komplett (Switches/APs mit Uplink) für den Netzplan

    @property
    def enabled(self):
        return bool(UNIFI_URL and UNIFI_USER and UNIFI_PASSWORD)

    def _open(self, url, payload=None):
        headers = {"Accept": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        r = opener.open(req, timeout=20)
        for c in r.headers.get_all("Set-Cookie") or []:
            k, _, rest = c.partition("=")
            self.cookies[k.strip()] = rest.split(";", 1)[0]
        tok = r.headers.get("X-CSRF-Token") or r.headers.get("X-Updated-CSRF-Token")
        if tok:
            self.csrf = tok
        return json.loads(r.read().decode() or "null")

    def login(self):
        self.cookies, self.csrf = {}, ""
        path = "/api/auth/login" if UNIFI_IS_OS else "/api/login"
        self._open(UNIFI_URL + path, {"username": UNIFI_USER, "password": UNIFI_PASSWORD, "remember": True})

    def _get(self, path):
        url = f"{self.base}/api/s/{UNIFI_SITE}/{path}"
        try:
            if not self.cookies:
                self.login()
            return self._open(url)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.login()
                return self._open(url)
            raise

    def _devices(self):
        if time.time() - self.ap_names_ts > 600:
            try:
                res = self._get("stat/device")
                self.dev_list = res.get("data", []) or []
                self.ap_names = {norm_mac(d.get("mac")): d.get("name") or d.get("model") or ""
                                 for d in self.dev_list}
                self.ap_names_ts = time.time()
            except Exception as e:
                log.debug("UniFi stat/device: %s", e)
        return self.ap_names

    def clients(self):
        """mac -> {ip, name, hostname, conn, vendor}. Nur aktuell verbundene Clients."""
        res = self._get("stat/sta")
        names = self._devices()
        out = {}
        now = time.time()
        for c in res.get("data", []):
            mac = norm_mac(c.get("mac"))
            ip = c.get("ip") or c.get("last_ip") or ""
            if not mac:
                continue
            if c.get("last_seen") and now - c["last_seen"] > 300:
                continue
            if c.get("is_wired"):
                sw = names.get(norm_mac(c.get("sw_mac")), "") or "Switch"
                conn = f"🔌 {sw}" + (f" Port {c['sw_port']}" if c.get("sw_port") else "")
            else:
                ap = names.get(norm_mac(c.get("ap_mac")), "") or "AP"
                conn = f"📶 {c.get('essid', '')} @ {ap}"
                if c.get("signal"):
                    conn += f" ({c['signal']} dBm)"
            out[mac] = {"ip": ip, "name": c.get("name") or "", "hostname": c.get("hostname") or "",
                        "conn": conn.strip(), "vendor": c.get("oui") or "",
                        "wired": bool(c.get("is_wired")), "sw_mac": norm_mac(c.get("sw_mac")),
                        "sw_port": c.get("sw_port") or 0, "ap_mac": norm_mac(c.get("ap_mac")),
                        "essid": c.get("essid") or ""}
        return out


unifi = UniFi()

# --------------------------------------------------------------------------
# Telegram
# --------------------------------------------------------------------------


class TelegramError(Exception):
    def __init__(self, msg, retry_after=0):
        super().__init__(msg)
        self.retry_after = retry_after


def tg_api(method, payload, timeout=15):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/{method}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        desc = body.get("description") or f"HTTP {e.code}"
        retry = (body.get("parameters") or {}).get("retry_after", 0)
        raise TelegramError(desc, retry)
    except urllib.error.URLError as e:
        raise TelegramError(f"api.telegram.org nicht erreichbar: {e.reason}")


tg_queue = queue.Queue()
tg_state = {"last_error": "", "last_ok": 0}


def tg_send_now(text, chat_id=None):
    """Sofort senden, mit Wiederholung bei Rate-Limit. Gibt (ok, fehler) zurück."""
    if not TG_TOKEN or not (chat_id or TG_CHAT):
        return False, "Telegram nicht konfiguriert (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID fehlen)"
    payload = {"chat_id": chat_id or TG_CHAT, "text": text,
               "parse_mode": "HTML", "disable_web_page_preview": True}
    err = ""
    for attempt in range(5):
        try:
            tg_api("sendMessage", payload)
            tg_state["last_ok"] = int(time.time())
            tg_state["last_error"] = ""
            return True, ""
        except TelegramError as e:
            err = str(e)
            if e.retry_after:                      # 429 Too Many Requests
                time.sleep(e.retry_after + 1)
                continue
            if "can't parse entities" in err:      # Formatierungsproblem -> ohne HTML senden
                payload.pop("parse_mode", None)
                continue
            if "nicht erreichbar" in err and attempt < 4:
                time.sleep(5 * (attempt + 1))
                continue
            break
    tg_state["last_error"] = err
    log.warning("Telegram-Fehler: %s", err)
    return False, err


def tg_send(text, chat_id=None, event_id=None):
    """In die Warteschlange legen (blockiert den Scan nicht)."""
    if not TG_TOKEN or not (chat_id or TG_CHAT):
        set_event_tg(event_id, "error: Telegram nicht konfiguriert")
        return False
    tg_queue.put((text, chat_id, event_id))
    return True


def tg_worker():
    while True:
        text, chat_id, event_id = tg_queue.get()
        ok, err = tg_send_now(text, chat_id)
        set_event_tg(event_id, "sent" if ok else f"error: {err}")
        time.sleep(1.1)  # Telegram erlaubt ca. 1 Nachricht/Sekunde pro Chat


def esc(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fmt_device(d):
    lines = [f"<b>{esc(display_name(d))}</b>"]
    if d.get("hostname") and d.get("hostname") != display_name(d):
        lines.append(f"Hostname: {esc(d['hostname'])}")
    lines.append(f"{esc(vlan_label(d['vlan']))} · {esc(d['ip'])}")
    lines.append(f"<code>{esc(d['mac'])}</code> {esc(d['vendor'])}".strip()
                 + (" · private MAC" if is_random_mac(d.get("mac")) else ""))
    if d.get("conn"):
        lines.append(esc(d["conn"]))
    return "\n".join(lines)


def fmt_new_device(d):
    return ("🆕 <b>Neues Gerät im Netz</b>\n"
            f"Name: <b>{esc(d.get('unifi_name') or d.get('hostname') or 'unbekannt (kein Hostname gemeldet)')}</b>\n"
            + (f"Hostname: {esc(d['hostname'])}\n" if d.get("unifi_name") and d.get("hostname") else "")
            + (f"Verbindung: {esc(d['conn'])}\n" if d.get("conn") else "") +
            f"Hersteller: {esc(d.get('vendor') or '-')}\n"
            f"{esc(vlan_label(d['vlan']))} · IP {esc(d['ip'])}\n"
            f"MAC <code>{esc(d['mac'])}</code>\n"
            f"Interface: {esc(d.get('interface') or '-')}")


def find_devices(devs, arg):
    """Erst exakter Treffer (Name, Hostname, IP, MAC), dann Teiltreffer."""
    arg = arg.lower()
    def fields(d):
        return [(d.get("name") or "").lower(), (d.get("unifi_name") or "").lower(),
                (d.get("hostname") or "").lower(), d.get("ip") or "", d.get("mac") or ""]
    exact = [d for d in devs if arg in fields(d)]
    if exact:
        return exact
    return [d for d in devs if any(arg in f for f in fields(d) if f)]


def tg_bot_loop():
    """Einfache Bot-Befehle per Long-Polling."""
    offset = int(kv_get("tg_offset", "0"))
    log.info("Telegram-Bot-Befehle aktiv")
    try:  # Befehlsmenü in Telegram anzeigen
        tg_api("setMyCommands", {"commands": [
            {"command": "check", "description": "Onlinestatus eines Geräts (Name/IP/MAC)"},
            {"command": "online", "description": "Alle Geräte online [vlan]"},
            {"command": "offline", "description": "Alle Geräte offline [vlan]"},
            {"command": "status", "description": "Übersicht"},
            {"command": "scan", "description": "Sofort scannen"},
            {"command": "traffic", "description": "Traffic eines Geräts (Name/IP/MAC)"},
            {"command": "top", "description": "Top-Verbraucher [live|24h|7d|30d] [vlan]"},
        ]})
    except Exception as e:
        log.debug("setMyCommands: %s", e)
    while True:
        try:
            res = tg_api("getUpdates", {"timeout": 50, "offset": offset}, timeout=60)
            for upd in res.get("result", []):
                offset = upd["update_id"] + 1
                kv_set("tg_offset", offset)
                msg = upd.get("message") or {}
                chat = str((msg.get("chat") or {}).get("id", ""))
                text = (msg.get("text") or "").strip()
                if not text.startswith("/") or chat != str(TG_CHAT):
                    continue
                tg_send_now(handle_command(text), chat)
        except Exception as e:
            log.debug("Telegram-Polling: %s", e)
            time.sleep(10)


def handle_command(text):
    cmd, _, arg = text.partition(" ")
    cmd = cmd.split("@")[0].lower()
    arg = arg.strip().lower()
    devs = list_devices()
    if cmd in ("/online", "/offline"):
        want = 1 if cmd == "/online" else 0
        sel = [d for d in devs if d["online"] == want]
        if arg:
            sel = [d for d in sel if str(d["vlan"]) == arg]
        if not sel:
            return "Keine Geräte."
        lines, cur = [], None
        for d in sorted(sel, key=lambda d: (d["vlan"] or 999, ip_sort_key(d["ip"]))):
            if d["vlan"] != cur:
                cur = d["vlan"]
                lines.append(f"\n<b>{esc(vlan_label(cur))}</b>")
            lines.append(f"{'🟢' if want else '🔴'} {esc(display_name(d))} – {esc(d['ip'])}")
        return ("Online" if want else "Offline") + f" ({len(sel)}):" + "\n".join(lines)
    if cmd in ("/check", "/status"):
        if not arg:
            on = sum(d["online"] for d in devs)
            return f"{on} von {len(devs)} Geräten online.\nNutze /check &lt;name|ip|mac&gt;"
        hits = find_devices(devs, arg)
        if not hits:
            return f"Kein Gerät „{esc(arg)}“ gefunden."
        hits = hits[:10]
        live = {}
        if cmd == "/check" and ONLINE_MODE != "arp":
            # Live-Ping, damit die Antwort aktuell ist und nicht vom letzten Scan stammt
            with ThreadPoolExecutor(max_workers=10) as ex:
                live = dict(zip([d["id"] for d in hits], ex.map(lambda d: ping(d["ip"]) if d["ip"] else False, hits)))
        out = []
        for d in hits:
            ts = datetime.fromtimestamp(d["last_seen"]).strftime("%d.%m. %H:%M") if d["last_seen"] else "-"
            if d["id"] in live:
                if live[d["id"]]:
                    status = "🟢 online (antwortet auf Ping)"
                elif d["online"]:
                    status = "🟡 kein Ping, laut Firewall aber noch aktiv"
                else:
                    status = "🔴 offline"
            else:
                status = "🟢 online" if d["online"] else "🔴 offline"
            out.append(f"{status}\n{fmt_device(d)}\nZuletzt gesehen: {ts}")
        return "\n\n".join(out)
    if cmd == "/scan":
        threading.Thread(target=scan_once, daemon=True).start()
        return "Scan gestartet."
    if cmd == "/traffic":
        return cmd_traffic(devs, arg)
    if cmd == "/top":
        return cmd_top(devs, arg)
    return ("Befehle:\n/check NAME – Onlinestatus prüfen (live, auch IP oder MAC)\n"
            "/online [vlan] – Geräte online\n/offline [vlan] – Geräte offline\n"
            "/status – Übersicht\n/scan – sofort scannen\n"
            "/traffic NAME – Traffic eines Geräts\n/top [live|24h|7d|30d] [vlan] – Top-Verbraucher")


def traffic_problem():
    if not TRAFFIC_ENABLED:
        return "Traffic-Erfassung ist ausgeschaltet (TRAFFIC_ENABLED=false)."
    if traffic_state["error"]:
        return "⚠️ " + esc(traffic_state["error"])
    if not traffic_state["last"]:
        return "Noch keine Traffic-Daten – erste Abfrage läuft."
    return ""


def cmd_traffic(devs, arg):
    prob = traffic_problem()
    if not arg:
        live = sum(rx + tx for rx, tx in live_rates.values())
        rx24 = sum(v[0] for v in traffic_totals("24h").values())
        tx24 = sum(v[1] for v in traffic_totals("24h").values())
        return ((prob + "\n\n" if prob else "") +
                f"📊 <b>Traffic gesamt</b>\nLive: {fmt_rate(live)} ({len(live_rates)} aktive Geräte)\n"
                f"24 h: ↓ {fmt_bytes(rx24)} · ↑ {fmt_bytes(tx24)}\n\nNutze /traffic &lt;name|ip|mac&gt; oder /top")
    hits = find_devices(devs, arg)
    if not hits:
        return f"Kein Gerät „{esc(arg)}“ gefunden."
    out = []
    for d in hits[:5]:
        rx, tx = live_rates.get(d["id"], (0.0, 0.0))
        lines = [f"📊 <b>{esc(display_name(d))}</b>", f"{esc(vlan_label(d['vlan']))} · {esc(d['ip'])}",
                 f"Live: ↓ {fmt_rate(rx)} · ↑ {fmt_rate(tx)}"]
        for rng, label in (("today", "Heute"), ("24h", "24 h"), ("7d", "7 Tage"), ("30d", "30 Tage")):
            a, b = traffic_totals(rng, device=d["id"]).get(d["id"], (0, 0))
            lines.append(f"{label}: ↓ {fmt_bytes(a)} · ↑ {fmt_bytes(b)}")
        st = alert_state.get(d["id"])
        if st and st.get("alerted"):
            lines.append("⚠️ Traffic-Alarm aktiv")
        out.append("\n".join(lines))
    if len(hits) > 5:
        out.append(f"… und {len(hits) - 5} weitere Treffer")
    return (prob + "\n\n" if prob else "") + "\n\n".join(out)


def cmd_top(devs, arg):
    rng, vlan = "", None
    for a in arg.split():
        a = a.replace("tage", "d").replace("h24", "24h")
        if a in ("live", "24h", "7d", "30d", "heute", "today"):
            rng = "today" if a in ("heute", "today") else a
        elif a.isdigit():
            vlan = int(a)
    by_id = {d["id"]: d for d in devs}
    labels = {"live": "jetzt", "today": "heute", "24h": "letzte 24 h", "7d": "letzte 7 Tage", "30d": "letzte 30 Tage"}

    def block(r, n):
        vals = dict(live_rates) if r == "live" else traffic_totals(r, vlan=vlan)
        rows = [(by_id[i], rx, tx) for i, (rx, tx) in vals.items()
                if i in by_id and (vlan is None or by_id[i]["vlan"] == vlan) and rx + tx > 0]
        rows.sort(key=lambda x: -(x[1] + x[2]))
        f = fmt_rate if r == "live" else fmt_bytes
        head = f"<b>Top {labels[r]}</b>" + (f" · {esc(vlan_label(vlan))}" if vlan is not None else "")
        if not rows:
            return head + "\nkeine Daten"
        lines = [head] + [f"{i}. {esc(display_name(d))} – ↓ {f(rx)} · ↑ {f(tx)}"
                          for i, (d, rx, tx) in enumerate(rows[:n], 1)]
        if r != "live" and vlan is None:
            per = {}
            for d, rx, tx in rows:
                per[d["vlan"]] = per.get(d["vlan"], 0) + rx + tx
            lines.append("<i>Pro VLAN:</i> " + " · ".join(
                f"{esc(vlan_label(v).split(' · ')[0])} {fmt_bytes(t)}" for v, t in sorted(per.items(), key=lambda x: -x[1])[:6]))
        return "\n".join(lines)

    prob = traffic_problem()
    parts = [block(rng, 10)] if rng else [block("live", 5), block("24h", 10)]
    return (prob + "\n\n" if prob else "") + "\n\n".join(parts)


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

scan_lock = threading.Lock()
state = {"last_scan": 0, "last_error": "", "duration": 0, "unifi_error": ""}


def ping(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=PING_TIMEOUT + 2)
        return r.returncode == 0
    except Exception:
        return False


def list_devices():
    with db_lock:
        return [dict(r) for r in db().execute("SELECT * FROM devices")]


def scan_once():
    if not scan_lock.acquire(blocking=False):
        return
    t0 = time.time()
    try:
        now = int(t0)
        arp = opn.arp()
        try:
            leases = opn.leases()
        except Exception as e:
            log.debug("Leases nicht verfügbar: %s", e)
            leases = []
        lease_by_mac = {l["mac"]: l for l in leases}

        # Für die Traffic-Zuordnung merken, an welchem Interface jede IP hängt
        intf_map = {(e.get("ip") or "").strip(): e.get("intf") or "" for e in arp if e.get("intf")}
        arp_intf.clear()
        arp_intf.update(intf_map)

        # Was die Firewall gerade sieht: (mac, vlan) -> info
        seen = {}
        for e in arp:
            mac = norm_mac(e.get("mac"))
            ip = (e.get("ip") or "").strip()
            if not mac or not ip:
                continue
            if not INCLUDE_FIREWALL and str(e.get("permanent")).lower() in ("true", "1", "yes"):
                continue
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            v = vlan_of(ip)
            if v is None:
                continue
            expired = str(e.get("expired")).lower() in ("true", "1", "yes")
            host = e.get("hostname") or lease_by_mac.get(mac, {}).get("hostname", "")
            seen[(mac, v)] = {
                "ip": ip, "hostname": host or "", "vendor": e.get("manufacturer") or "",
                "interface": e.get("intf_description") or e.get("intf") or "",
                "arp_ok": not expired, "unifi_ok": False, "unifi_name": "", "conn": "",
            }
        # Leases ergänzen (Geräte mit Lease, aber ohne ARP-Eintrag)
        for l in leases:
            v = vlan_of(l["ip"])
            if v is None:
                continue
            key = (l["mac"], v)
            if key not in seen:
                seen[key] = {"ip": l["ip"], "hostname": l["hostname"], "vendor": "", "interface": "",
                             "arp_ok": False, "unifi_ok": False, "unifi_name": "", "conn": ""}
        # UniFi-Clients: verbunden = online, plus Aliasname und Verbindung (AP/SSID/Switch-Port)
        uni = {}
        if unifi.enabled:
            try:
                uni = unifi.clients()
                uni_links.clear()
                uni_links.update({m: {k: c[k] for k in ("wired", "sw_mac", "sw_port", "ap_mac", "essid")}
                                  for m, c in uni.items()})
                state["unifi_error"] = ""
            except Exception as e:
                state["unifi_error"] = f"{type(e).__name__}: {e}"
                log.warning("UniFi-Abfrage fehlgeschlagen: %s", e)
        for mac, c in uni.items():
            v = vlan_of(c["ip"]) if c["ip"] else None
            if v is None:
                continue
            key = (mac, v)
            info = seen.setdefault(key, {"ip": c["ip"], "hostname": c["hostname"], "vendor": c["vendor"],
                                         "interface": "", "arp_ok": False})
            info["unifi_ok"] = True
            info["unifi_name"] = c["name"]
            info["conn"] = c["conn"]
            if not info.get("hostname"):
                info["hostname"] = c["hostname"]
            if not info.get("vendor"):
                info["vendor"] = c["vendor"]

        with db_lock:
            known = {(r["mac"], r["vlan"]): dict(r) for r in db().execute("SELECT * FROM devices")}
        first_scan = not known

        # Neue Geräte anlegen – vorher prüfen, ob es ein bekanntes Gerät ist, das nur
        # das WLAN/VLAN gewechselt hat oder eine neue private MAC verwendet
        new_devices, moves = [], []
        with db_lock:
            for key, info in seen.items():
                if key in known:
                    continue
                mac, v = key
                host = (info.get("hostname") or "").strip().lower()
                uname = (info.get("unifi_name") or "").strip().lower()

                def same_device(k, d):
                    if k in seen:            # alter Eintrag ist gerade selbst aktiv -> anderes Gerät
                        return False
                    if k[0] == mac:          # gleiche MAC, anderes VLAN (z. B. zweites WLAN)
                        return True
                    if MERGE_RANDOM_MAC and is_random_mac(mac) and (host or uname):
                        return ((host and (d.get("hostname") or "").strip().lower() == host) or
                                (uname and (d.get("unifi_name") or "").strip().lower() == uname))
                    return False

                cand = [d for k, d in known.items() if same_device(k, d)]
                if cand:
                    # bevorzugt gleiche MAC, sonst zuletzt gesehenes Gerät
                    old = max(cand, key=lambda d: (d["mac"] == mac, d.get("last_seen") or 0))
                    old_key = (old["mac"], old["vlan"])
                    try:
                        db().execute("UPDATE devices SET mac=?, vlan=? WHERE id=?", (mac, v, old["id"]))
                    except sqlite3.IntegrityError:
                        pass
                    else:
                        known.pop(old_key, None)
                        moves.append((old, dict(old), info))
                        old["mac"], old["vlan"] = mac, v
                        known[key] = old
                        continue

                cur = db().execute(
                    "INSERT INTO devices(mac,vlan,ip,hostname,vendor,interface,unifi_name,conn,first_seen,"
                    "last_seen,online,fails,watch,changed_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,0,?,?)",
                    (mac, v, info["ip"], info["hostname"], info["vendor"], info["interface"],
                     info.get("unifi_name", ""), info.get("conn", ""),
                     now, None, 1 if WATCH_DEFAULT else 0, now))
                d = dict(db().execute("SELECT * FROM devices WHERE id=?", (cur.lastrowid,)).fetchone())
                known[key] = d
                new_devices.append(d)
            db().commit()

        moved_ids = {m[0]["id"] for m in moves}

        # Online-Prüfung
        targets = {}
        for key, d in known.items():
            ip = seen.get(key, {}).get("ip") or d["ip"]
            if ip:
                targets[key] = ip
        ping_ok = {}
        if ONLINE_MODE in ("ping", "ping_or_arp") and targets:
            with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
                for key, ok in zip(targets.keys(), ex.map(ping, targets.values())):
                    ping_ok[key] = ok

        events = []
        with db_lock:
            for key, d in known.items():
                info = seen.get(key)
                arp_ok = bool(info and info["arp_ok"])
                uni_ok = bool(info and info.get("unifi_ok"))
                if ONLINE_MODE == "arp":
                    alive = arp_ok or uni_ok
                elif ONLINE_MODE == "ping":
                    alive = ping_ok.get(key, False) or uni_ok
                else:
                    alive = ping_ok.get(key, False) or arp_ok or uni_ok

                fails = 0 if alive else d["fails"] + 1
                online = d["online"]
                changed = d["changed_at"]
                if alive and not online:
                    online, changed = 1, now
                    if d["last_seen"]:  # nicht beim allerersten Sehen melden
                        events.append(("online", d))
                elif not alive and online and fails >= OFFLINE_AFTER:
                    online, changed = 0, now
                    events.append(("offline", d))

                fields = {"online": online, "fails": fails, "changed_at": changed}
                if alive:
                    fields["last_seen"] = now
                if info:
                    fields["ip"] = info["ip"]
                    if info["hostname"]:
                        fields["hostname"] = info["hostname"]
                    if info["vendor"]:
                        fields["vendor"] = info["vendor"]
                    if info["interface"]:
                        fields["interface"] = info["interface"]
                    if info.get("unifi_name"):
                        fields["unifi_name"] = info["unifi_name"]
                    if info.get("conn"):
                        fields["conn"] = info["conn"]
                if info and d["ip"] and info["ip"] != d["ip"] and d["id"] not in moved_ids:
                    events.append(("ipchange", {**d, "old_ip": d["ip"], "ip": info["ip"]}))
                sets = ",".join(f"{k}=?" for k in fields)
                db().execute(f"UPDATE devices SET {sets} WHERE id=?", (*fields.values(), d["id"]))
            db().commit()

        notify = notify_event
        if first_scan and new_devices:
            # Erster Scan: eine Zusammenfassung statt einer Nachricht pro Gerät
            for d in new_devices:
                add_event(d["id"], "new", f"Erfasst beim ersten Scan: {display_name(d)} ({d['ip']})")
            per_vlan = {}
            for d in new_devices:
                per_vlan[d["vlan"]] = per_vlan.get(d["vlan"], 0) + 1
            lines = [f"{esc(vlan_label(v))}: {n}" for v, n in sorted(per_vlan.items(), key=lambda x: x[0] or 999)]
            notify(None, "info", f"Erster Scan: {len(new_devices)} Geräte erfasst",
                   f"📋 <b>NetWatch gestartet</b>\n{len(new_devices)} Geräte erfasst:\n" + "\n".join(lines)
                   + "\n\nAb jetzt kommt bei jedem neuen Gerät eine Nachricht.", NOTIFY_NEW)
        else:
            for d in new_devices:
                rnd = is_random_mac(d["mac"])
                msg = fmt_new_device(d)
                if rnd:
                    msg += ("\n\nℹ️ <i>Private (zufällige) MAC-Adresse – kann auch ein bekanntes Gerät sein, "
                            "das eine neue Adresse verwendet.</i>")
                notify(d["id"], "new", f"Neues Gerät: {display_name(d)} ({d['ip']})" + (" · private MAC" if rnd else ""),
                       msg, NOTIFY_NEW and (NOTIFY_RANDOM_MAC or not rnd))
        for d, before, info in moves:
            d = dict(d)
            for k in ("ip", "conn", "hostname"):
                if info.get(k):
                    d[k] = info[k]
            parts, tg_parts = [], []
            if before["vlan"] != d["vlan"]:
                parts.append(f"{vlan_label(before['vlan'])} → {vlan_label(d['vlan'])}")
                tg_parts.append(f"Vorher: {esc(vlan_label(before['vlan']))} · {esc(before['ip'])}")
            if before["mac"] != d["mac"]:
                parts.append(f"neue private MAC {before['mac']} → {d['mac']}")
                tg_parts.append(f"Vorherige MAC: <code>{esc(before['mac'])}</code>")
            kind = "vlanchange" if before["vlan"] != d["vlan"] else "macchange"
            title = "🔀 <b>Wechselt WLAN/VLAN</b>" if kind == "vlanchange" else "🔄 <b>Neue private MAC</b>"
            notify(d["id"], kind, f"{display_name(d)}: " + ", ".join(parts),
                   f"{title}\n{fmt_device(d)}\n" + "\n".join(tg_parts), bool(d["watch"]))
        for kind, d in events:
            if kind == "online":
                notify(d["id"], kind, f"{display_name(d)} ist online",
                       "🟢 <b>Online</b>\n" + fmt_device(d), bool(d["watch"]))
            elif kind == "offline":
                notify(d["id"], kind, f"{display_name(d)} ist offline",
                       "🔴 <b>Offline</b>\n" + fmt_device(d), bool(d["watch"]))
            elif kind == "ipchange":
                notify(d["id"], kind, f"{display_name(d)}: IP {d['old_ip']} → {d['ip']}",
                       f"🔁 <b>IP geändert</b> {esc(d['old_ip'])} → {esc(d['ip'])}\n" + fmt_device(d),
                       bool(d["watch"]))

        state["last_error"] = ""
        log.info("Scan: %d ARP, %d Leases, %d Geräte, %d neu", len(arp), len(leases), len(known), len(new_devices))
    except Exception as e:
        state["last_error"] = f"{type(e).__name__}: {e}"
        log.error("Scan fehlgeschlagen: %s", state["last_error"])
    finally:
        state["last_scan"] = int(time.time())
        state["duration"] = round(time.time() - t0, 1)
        scan_lock.release()


def notify_event(dev_id, kind, text, tg_text, send):
    """Ereignis speichern und optional per Telegram senden."""
    eid = add_event(dev_id, kind, text, "queued" if send and TG_TOKEN and TG_CHAT else "")
    if send:
        tg_send(tg_text, event_id=eid)


def scanner_loop():
    while True:
        scan_once()
        time.sleep(SCAN_INTERVAL)



# --------------------------------------------------------------------------
# Traffic
# --------------------------------------------------------------------------
#
# Live: /api/diagnostics/traffic/top/<interfaces> (iftop auf der Firewall) liefert pro Adresse die
# aktuelle Rate. Daraus werden alle TRAFFIC_INTERVAL Sekunden Bytes hochgerechnet (Rate × Zeit)
# und pro Gerät und Stunde in SQLite addiert. Ist Insight (Netflow, „Capture local“) aktiv, werden
# abgeschlossene Stunden durch die genaueren Netflow-Summen ersetzt.
#
# Die Firewall sieht nur Verkehr, der über sie läuft: ins Internet und zwischen VLANs –
# nicht zwischen zwei Geräten im selben VLAN.

arp_intf = {}           # ip -> Interface-Gerätename aus der ARP-Tabelle (z. B. vlan0.20)
live_rates = {}         # device_id -> (rx B/s, tx B/s)
alert_state = {}        # device_id -> {"since", "alerted", "peak"}
traffic_state = {"error": "", "last": 0, "duration": 0, "interfaces": [], "hosts": 0,
                 "insight": "aus" if TRAFFIC_INSIGHT == "false" else "noch nicht geprüft",
                 "insight_error": "", "insight_last": 0}
_ifinfo = {"ts": 0, "data": {}}
_last_poll = {"ts": 0}

RANGES = {  # Name -> (Tabelle, Bucketgröße s, Anzahl Buckets)
    "24h": ("h", 3600, 24),
    "7d": ("h", 6 * 3600, 28),
    "30d": ("d", 86400, 30),
}


def day_start(ts):
    """Lokale Mitternacht (Container-TZ) des Zeitpunkts."""
    d = datetime.fromtimestamp(ts).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(time.mktime(d.timetuple()))


def next_day(ts):
    return day_start(day_start(ts) + 86400 + 3 * 3600)   # +3 h fängt Sommer-/Winterzeit ab


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            if unit == "B":
                return f"{int(n)} B"
            return (f"{n:.1f}" if n < 100 else f"{n:.0f}").replace(".", ",") + f" {unit}"
        n /= 1000


def fmt_rate(n):
    return fmt_bytes(n) + "/s"


def traffic_ifaces(force=False):
    """Interface-Liste der OPNsense (gecacht, 10 min)."""
    if force or not _ifinfo["data"] or time.time() - _ifinfo["ts"] > 600:
        _ifinfo["data"] = opn.traffic_interfaces()
        _ifinfo["ts"] = time.time()
    return _ifinfo["data"]


def pick_ifaces(info):
    """Welche Interfaces abgefragt werden: TRAFFIC_INTERFACES oder alle, an denen Geräte hängen."""
    if TRAFFIC_INTERFACES:
        return TRAFFIC_INTERFACES
    used = set(arp_intf.values())
    keys = [k for k, v in info.items() if v["device"] in used or k in used]
    if keys:
        return sorted(keys)
    return sorted(k for k, v in info.items()
                  if not k.startswith(("wan", "lo")) and "wan" not in (v["name"] or "").lower())


def parse_top(res, info):
    """Top-Talker-Antwort -> ip -> (rx B/s, tx B/s).

    Ein Gerät kann auf mehreren Interfaces auftauchen (Verkehr zwischen VLANs sieht die Firewall
    auf beiden Seiten). Genommen wird der Eintrag vom eigenen Interface laut ARP-Tabelle, sonst der
    größte – nie die Summe, sonst würde Inter-VLAN-Verkehr doppelt gezählt.
    """
    dev2key = {v["device"]: k for k, v in info.items() if v.get("device")}
    cands = {}
    for ifname, block in (res or {}).items():
        if not isinstance(block, dict):
            continue
        idents = {ifname, (info.get(ifname) or {}).get("device", ""), dev2key.get(ifname, "")} - {""}
        for r in block.get("records") or []:
            ip = (r.get("address") or "").strip()
            if not ip:
                continue
            try:
                rin = float(r.get("rate_bits_in") or 0) / 8
                rout = float(r.get("rate_bits_out") or 0) / 8
            except (TypeError, ValueError):
                continue
            rx, tx = (rout, rin) if TRAFFIC_SWAP else (rin, rout)
            cands.setdefault(ip, []).append((idents, rx, tx))
    out = {}
    for ip, lst in cands.items():
        own = arp_intf.get(ip)
        match = [c for c in lst if own and own in c[0]]
        best = match[0] if match else max(lst, key=lambda c: c[1] + c[2])
        out[ip] = (best[1], best[2])
    return out


def devices_by_ip(devs):
    """IP -> Gerät (bei doppelten IPs: online vor offline, dann zuletzt gesehen)."""
    out = {}
    for d in sorted(devs, key=lambda d: (d["online"], d["last_seen"] or 0)):
        if d["ip"]:
            out[d["ip"]] = d
    return out


def recompute_daily(device_ids, days):
    """Tageswerte aus den Stundenwerten neu berechnen (hält beide Tabellen konsistent)."""
    if not device_ids:
        return
    ids = ",".join(str(int(i)) for i in set(device_ids))
    for day in set(days):
        db().execute(
            f"INSERT OR REPLACE INTO traffic_daily(device, ts, rx, tx) "
            f"SELECT device, ?, SUM(rx), SUM(tx) FROM traffic_hourly "
            f"WHERE ts >= ? AND ts < ? AND device IN ({ids}) GROUP BY device",
            (day, day, next_day(day)))


def add_traffic(amounts, ts):
    """amounts: device_id -> (rx_bytes, tx_bytes) für den Zeitpunkt ts (Live-Hochrechnung)."""
    hour = int(ts) - int(ts) % 3600
    rows = [(dev, hour, int(rx), int(tx)) for dev, (rx, tx) in amounts.items() if rx >= 1 or tx >= 1]
    if not rows:
        return
    with db_lock:
        db().executemany(
            "INSERT INTO traffic_hourly(device, ts, rx, tx, src) VALUES(?,?,?,?,'live') "
            "ON CONFLICT(device, ts) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx "
            "WHERE traffic_hourly.src = 'live'", rows)       # Insight-Stunden nicht überschreiben
        recompute_daily([r[0] for r in rows], [day_start(hour)])
        db().commit()


def traffic_poll():
    t0 = time.time()
    info = traffic_ifaces()
    if not info:
        raise RuntimeError("OPNsense liefert keine Interfaces unter /api/diagnostics/traffic/interface")
    keys = pick_ifaces(info)
    unknown = [k for k in keys if k not in info]
    if unknown:
        raise RuntimeError(f"TRAFFIC_INTERFACES: unbekannte Interfaces {', '.join(unknown)} – "
                           f"verfügbar: {', '.join(sorted(info))}")
    res = opn.traffic_top(keys)
    rates = parse_top(res, info)
    now = time.time()
    devs = list_devices()
    by_ip = devices_by_ip(devs)
    live = {}
    for ip, (rx, tx) in rates.items():
        d = by_ip.get(ip)
        if not d:
            continue                        # Adressen im Internet / unbekannte Geräte
        a, b = live.get(d["id"], (0.0, 0.0))
        live[d["id"]] = (a + rx, b + tx)
    dt = now - _last_poll["ts"] if _last_poll["ts"] else TRAFFIC_INTERVAL
    dt = max(1.0, min(dt, 3 * TRAFFIC_INTERVAL))   # nach Ausfällen nicht riesig hochrechnen
    _last_poll["ts"] = now
    live_rates.clear()
    live_rates.update(live)
    add_traffic({dev: (rx * dt, tx * dt) for dev, (rx, tx) in live.items()}, now)
    traffic_state.update(error="", last=int(now), duration=round(now - t0, 1), hosts=len(live),
                         interfaces=[f"{info[k]['name']} ({k})" for k in keys])
    check_alerts(devs, now)
    if not res:
        traffic_state["error"] = ("Top Talker lieferte keine Daten – Interfaces prüfen "
                                  f"(abgefragt: {', '.join(keys)})")


def check_alerts(devs, now):
    """Alarm, wenn ein beobachtetes Gerät TRAFFIC_ALERT_MINUTES lang über der Schwelle liegt."""
    for d in devs:
        lim = d.get("traffic_limit")
        lim = TRAFFIC_ALERT_MBS if lim is None else lim
        if not d["watch"] or not lim or lim <= 0:
            alert_state.pop(d["id"], None)
            continue
        rx, tx = live_rates.get(d["id"], (0.0, 0.0))
        val = {"down": rx, "up": tx}.get(TRAFFIC_ALERT_DIRECTION, rx + tx)
        thr = lim * 1e6
        st = alert_state.setdefault(d["id"], {"since": None, "alerted": False, "peak": 0.0})
        what = {"down": "Download", "up": "Upload"}.get(TRAFFIC_ALERT_DIRECTION, "Traffic")
        if val >= thr:
            st["since"] = st["since"] or now
            st["peak"] = max(st["peak"], val)
            if not st["alerted"] and now - st["since"] >= TRAFFIC_ALERT_MINUTES * 60:
                st["alerted"] = True
                mins = round((now - st["since"]) / 60)
                notify_event(
                    d["id"], "traffic",
                    f"{display_name(d)}: hoher {what} seit {mins} min ({fmt_rate(val)})",
                    f"⚠️ <b>Hoher {what}</b> seit {mins} min\n{fmt_device(d)}\n"
                    f"Jetzt: ↓ {fmt_rate(rx)} · ↑ {fmt_rate(tx)}\n"
                    f"Schwelle: {fmt_rate(thr)}", True)
        elif val < thr * 0.8:                       # etwas Hysterese gegen Flattern
            if st["alerted"]:
                mins = round((now - st["since"]) / 60)
                notify_event(
                    d["id"], "traffic",
                    f"{display_name(d)}: {what} wieder normal (nach {mins} min, Spitze {fmt_rate(st['peak'])})",
                    f"✅ <b>{what} wieder normal</b>\n{esc(display_name(d))} – nach {mins} min, "
                    f"Spitze {fmt_rate(st['peak'])}", True)
            alert_state[d["id"]] = {"since": None, "alerted": False, "peak": 0.0}


def insight_import():
    """Abgeschlossene Stunden aus Insight übernehmen (genauer als die Live-Hochrechnung)."""
    if TRAFFIC_INSIGHT == "false":
        return
    if TRAFFIC_INSIGHT == "auto":
        en = opn.netflow_enabled()
        if en is False:
            traffic_state.update(insight="nicht aktiviert (Reporting → NetFlow → „Capture local“)",
                                 insight_error="")
            return
    info = _ifinfo["data"]
    dev2key = {v["device"]: k for k, v in info.items() if v.get("device")}
    now = int(time.time())
    cur_hour = now - now % 3600
    last_full = cur_hour - 3600 if now - cur_hour >= 600 else cur_hour - 7200  # Netflow schreibt verzögert
    done = int(kv_get("insight_upto", "0") or 0)
    start = max(done - 2 * 3600, last_full - (TRAFFIC_INSIGHT_BACKFILL - 1) * 3600)
    imported = 0
    for hour in range(start, last_full + 1, 3600):
        rows = opn.insight_top(hour, hour + 3600)
        by_ip = devices_by_ip(list_devices())
        per = {}
        for r in rows:
            ip = (r.get("src_addr") or "").strip()
            d = by_ip.get(ip)
            if not d:
                continue
            intf = str(r.get("if") or "")
            own = arp_intf.get(ip)
            idents = {intf, (info.get(intf) or {}).get("device", ""), dev2key.get(intf, "")} - {""}
            if own and len(idents) > 1 and own not in idents:
                continue                     # gleicher Verkehr auf dem anderen VLAN-Interface
            try:
                total = int(float(r.get("total", r.get("octets", 0)) or 0))
            except (TypeError, ValueError):
                continue
            rx, tx = per.get(d["id"], (0, 0))
            if str(r.get("direction")) == "in":    # ins Firewall-Interface hinein = vom Gerät gesendet
                tx += total
            else:
                rx += total
            per[d["id"]] = (rx, tx)
        if per:
            with db_lock:
                db().executemany(
                    "INSERT OR REPLACE INTO traffic_hourly(device, ts, rx, tx, src) VALUES(?,?,?,?,'insight')",
                    [(dev, hour, rx, tx) for dev, (rx, tx) in per.items()])
                recompute_daily(list(per), [day_start(hour)])
                db().commit()
            imported += 1
    kv_set("insight_upto", last_full)
    traffic_state.update(insight=f"aktiv – {imported} Stunde(n) übernommen" if imported or done
                         else "aktiv, aber keine Daten zu bekannten Geräten",
                         insight_error="", insight_last=now)


def traffic_cleanup():
    now = int(time.time())
    with db_lock:
        db().execute("DELETE FROM traffic_hourly WHERE ts < ?", (now - TRAFFIC_HOURLY_DAYS * 86400,))
        db().execute("DELETE FROM traffic_daily WHERE ts < ?", (now - TRAFFIC_DAILY_DAYS * 86400,))
        db().execute("DELETE FROM traffic_hourly WHERE device NOT IN (SELECT id FROM devices)")
        db().execute("DELETE FROM traffic_daily WHERE device NOT IN (SELECT id FROM devices)")
        db().commit()


def traffic_loop():
    time.sleep(8)        # erster Scan füllt die ARP-Zuordnung
    last_insight = last_clean = 0
    last_err = None
    while True:
        t0 = time.time()
        try:
            traffic_poll()
        except ApiPermissionError as e:
            traffic_state["error"] = str(e) + " – ohne dieses Recht gibt es keine Traffic-Daten."
        except Exception as e:
            traffic_state["error"] = f"{type(e).__name__}: {e}" if not isinstance(e, RuntimeError) else str(e)
            _ifinfo["ts"] = 0       # Interface-Liste beim nächsten Mal neu holen
        if traffic_state["error"] != last_err:
            last_err = traffic_state["error"]
            if last_err:
                log.warning("Traffic: %s", last_err)
            else:
                log.info("Traffic-Abfrage läuft (%s)", ", ".join(traffic_state["interfaces"]))
        if time.time() - last_insight > 600:
            last_insight = time.time()
            try:
                insight_import()
            except ApiPermissionError as e:
                traffic_state.update(insight="kein Zugriff", insight_error=str(e) +
                                     " – nur für den Verlauf aus Insight nötig, Live-Daten laufen trotzdem.")
            except Exception as e:
                traffic_state.update(insight="Fehler", insight_error=f"{type(e).__name__}: {e}")
                log.debug("Insight: %s", e)
        if time.time() - last_clean > 3600:
            last_clean = time.time()
            traffic_cleanup()
        time.sleep(max(1, TRAFFIC_INTERVAL - (time.time() - t0)))


# ---- Auswertungen ----

def range_window(rng, now=None):
    """(Tabelle, Liste der Bucket-Startzeiten, Ende)."""
    now = now or time.time()
    kind, size, count = RANGES[rng]
    if kind == "h" and size == 3600:
        end = int(now) - int(now) % 3600 + 3600
        return "h", [end - (count - i) * 3600 for i in range(count)], end
    if kind == "h":                                          # 6-h-Blöcke ab lokaler Mitternacht
        days = _last_days(now, count * size // 86400)
        starts = [int(time.mktime(datetime.fromtimestamp(d).replace(hour=h).timetuple()))
                  for d in days for h in range(0, 24, size // 3600)]
        return "h", starts, next_day(days[-1])
    days = _last_days(now, count)
    return "d", days, next_day(days[-1])


def _last_days(now, count):
    """Lokale Mitternachten der letzten count Tage (heute eingeschlossen), aufsteigend."""
    days, t = [], day_start(now)
    for _ in range(count):
        days.append(t)
        t = day_start(t - 3 * 3600)
    return days[::-1]


def _dev_filter(device=None, vlan=None):
    if device is not None:
        return " AND device = ?", [int(device)]
    if vlan is not None:
        return " AND device IN (SELECT id FROM devices WHERE vlan = ?)", [int(vlan)]
    return "", []


def traffic_series(rng, device=None, vlan=None):
    kind, starts, end = range_window(rng)
    table = "traffic_hourly" if kind == "h" else "traffic_daily"
    where, args = _dev_filter(device, vlan)
    with db_lock:
        rows = db().execute(f"SELECT ts, SUM(rx) rx, SUM(tx) tx FROM {table} WHERE ts >= ? AND ts < ?{where} "
                            "GROUP BY ts", [starts[0], end, *args]).fetchall()
    out = [{"ts": t, "rx": 0, "tx": 0} for t in starts]
    bounds = starts + [end]
    for r in rows:
        for i in range(len(starts)):
            if bounds[i] <= r["ts"] < bounds[i + 1]:
                out[i]["rx"] += r["rx"] or 0
                out[i]["tx"] += r["tx"] or 0
                break
    return out


def traffic_totals(rng, device=None, vlan=None):
    """Summen pro Gerät im Zeitraum: device_id -> (rx, tx). rng: today | 24h | 7d | 30d."""
    now = time.time()
    if rng == "today":
        table, since = "traffic_hourly", day_start(now)
    elif rng == "24h":
        table, since = "traffic_hourly", int(now) - int(now) % 3600 - 23 * 3600
    elif rng == "7d":
        table, since = "traffic_hourly", day_start(now - 6 * 86400)
    else:
        _, days, _ = range_window("30d")
        table, since = "traffic_daily", days[0]
    where, args = _dev_filter(device, vlan)
    with db_lock:
        rows = db().execute(f"SELECT device, SUM(rx) rx, SUM(tx) tx FROM {table} WHERE ts >= ?{where} "
                            "GROUP BY device", [since, *args]).fetchall()
    return {r["device"]: (r["rx"] or 0, r["tx"] or 0) for r in rows}


def traffic_status():
    return {
        "enabled": TRAFFIC_ENABLED, "error": traffic_state["error"], "last": traffic_state["last"],
        "duration": traffic_state["duration"], "interfaces": traffic_state["interfaces"],
        "hosts": traffic_state["hosts"], "interval": TRAFFIC_INTERVAL,
        "insight": traffic_state["insight"], "insight_error": traffic_state["insight_error"],
        "alert_mbs": TRAFFIC_ALERT_MBS, "alert_minutes": TRAFFIC_ALERT_MINUTES,
        "alert_direction": TRAFFIC_ALERT_DIRECTION,
    }


def api_traffic(qs):
    rng = qs.get("range", ["24h"])[0]
    if rng not in ("live", "today", "24h", "7d", "30d"):
        rng = "24h"
    vlan = qs.get("vlan", [""])[0]
    vlan = int(vlan) if vlan.lstrip("-").isdigit() else None
    devs = {d["id"]: d for d in list_devices()}
    vals = dict(live_rates) if rng == "live" else traffic_totals(rng, vlan=vlan)
    rows, per_vlan = [], {}
    for dev_id, (rx, tx) in vals.items():
        d = devs.get(dev_id)
        if not d or (vlan is not None and d["vlan"] != vlan) or (rx + tx) <= 0:
            continue
        rows.append({"id": dev_id, "name": display_name(d), "named": bool(d["name"]), "ip": d["ip"],
                     "vlan": d["vlan"], "online": d["online"], "rx": rx, "tx": tx})
        pv = per_vlan.setdefault(d["vlan"], [0, 0, 0])
        pv[0] += rx
        pv[1] += tx
        pv[2] += 1
    rows.sort(key=lambda r: r["rx"] + r["tx"], reverse=True)
    vlans = [{"id": v, "label": vlan_label(v), "rx": a, "tx": b, "devices": n}
             for v, (a, b, n) in sorted(per_vlan.items(), key=lambda x: -(x[1][0] + x[1][1]))]
    out = {"range": rng, "devices": rows[:100], "vlans": vlans,
           "total": {"rx": sum(r["rx"] for r in rows), "tx": sum(r["tx"] for r in rows), "devices": len(rows)},
           "status": traffic_status()}
    if rng in RANGES:
        out["series"] = traffic_series(rng, vlan=vlan)
    return out


def api_device_traffic(dev_id, qs):
    rng = qs.get("range", ["24h"])[0]
    rng = rng if rng in RANGES else "24h"
    totals = {}
    for r in ("today", "24h", "7d", "30d"):
        rx, tx = traffic_totals(r, device=dev_id).get(dev_id, (0, 0))
        totals[r] = {"rx": rx, "tx": tx}
    rx, tx = live_rates.get(dev_id, (0.0, 0.0))
    return {"range": rng, "series": traffic_series(rng, device=dev_id), "totals": totals,
            "live": {"rx": rx, "tx": tx}, "alert": alert_state.get(dev_id)}


# --------------------------------------------------------------------------
# Web-Server
# --------------------------------------------------------------------------


def api_events(qs):
    try:
        limit = max(1, min(int(qs.get("limit", ["300"])[0]), EVENT_KEEP))
    except ValueError:
        limit = 300
    kind = qs.get("kind", [""])[0]
    sql = ("SELECT e.*, d.name, d.unifi_name, d.hostname, d.ip, d.mac, d.vlan FROM events e "
           "LEFT JOIN devices d ON d.id = e.device")
    args = []
    if kind:
        sql += " WHERE e.kind = ?"
        args.append(kind)
    sql += " ORDER BY e.id DESC LIMIT ?"
    args.append(limit)
    with db_lock:
        rows = [dict(r) for r in db().execute(sql, args)]
        total = db().execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"events": rows, "total": total}


def api_state():
    devs = list_devices()
    devs.sort(key=lambda d: ip_sort_key(d["ip"]))
    for d in devs:
        d["rx_bps"], d["tx_bps"] = live_rates.get(d["id"], (0.0, 0.0))
        st = alert_state.get(d["id"])
        d["traffic_alert"] = bool(st and st.get("alerted"))
    vlans = []
    for v in VLANS + [0]:
        ds = [d for d in devs if d["vlan"] == v]
        if v == 0 and not ds:
            continue
        vlans.append({"id": v, "label": vlan_label(v), "subnet": f"{SUBNET_PREFIX}.{v}.0/24" if v else "",
                      "total": len(ds), "online": sum(d["online"] for d in ds)})
    return {
        "devices": devs, "vlans": vlans,
        "tg_error": tg_state["last_error"], "tg_last_ok": tg_state["last_ok"], "notify_new": NOTIFY_NEW,
        "last_scan": state["last_scan"], "last_error": state["last_error"],
        "duration": state["duration"], "interval": SCAN_INTERVAL,
        "telegram": bool(TG_TOKEN and TG_CHAT), "mode": ONLINE_MODE,
        "unifi": unifi.enabled, "unifi_error": state["unifi_error"], "unifi_names": UNIFI_USE_NAMES,
        "traffic": traffic_status(),
    }


# --------------------------------------------------------------------------
# Netzplan (Reiter „Netz“): Geräte aus der Datenbank, Switches/APs und ihre Uplinks
# aus UniFi, Verbindungen (Switch-Port / WLAN) aus dem letzten Scan. Eigene Geräte,
# Kabel, Namen, Typen, Notizen und Positionen liegen in kv "netmap".
# --------------------------------------------------------------------------
uni_links = {}   # mac -> {"wired", "sw_mac", "sw_port", "ap_mac", "essid"} aus dem letzten Scan
netmap_lock = threading.Lock()
CONN_RE = re.compile(r"^(?:🔌\s*(.+?)(?:\s+Port\s+(\d+))?|📶\s*(.*?)\s*@\s*(.+?)(?:\s*\((-?\d+) dBm\))?)$")


def guess_kind(*texts):
    """Gerätetyp grob aus Name/Hersteller raten."""
    t = " ".join(x or "" for x in texts).lower()
    has = lambda *ws: any(w in t for w in ws)
    if has("switch", "usw-", "usw ", "gs108", "gs308", "tl-sg"):
        return "switch"
    if has("access point", "u6-", "u6 ", "uap", "u7-", "nanohd", "unifi ap", "deco", "repeater"):
        return "ap"
    if has("iphone", "ipad", "android", "pixel", "galaxy", "handy", "phone", "xiaomi", "oneplus", "redmi", "tablet"):
        return "phone"
    if has("shelly", "tasmota", "sonoff", "esp-", "esp32", "esp8266", "espressif", "tuya", "hue", "zigbee", "echo",
           "alexa", "nest", "homematic", "tado", "smart", "meross", "wled", "home assistant", "homeassistant"):
        return "iot"
    if has("tv", "chromecast", "roku", "firetv", "fire tv", "appletv", "apple tv", "sonos", "playstation", "xbox",
           "nintendo", "receiver", "shield"):
        return "tv"
    if has("printer", "drucker", "brother", "epson", "canon", "laserjet", "officejet"):
        return "printer"
    if has("nas", "synology", "qnap", "truenas", "diskstation", "unraid"):
        return "nas"
    if has("opnsense", "pfsense", "firewall"):
        return "gateway"
    if has("fritz", "router", "speedport", "vodafone", "station"):
        return "router"
    if has("proxmox", "pve", "server", "docker", "lxc"):
        return "server"
    return "client"


def _speed(mbit):
    mbit = float(mbit or 0)
    if mbit >= 1000:
        return f"{int(mbit // 1000)}G" if mbit % 1000 == 0 else f"{mbit / 1000:.1f}G"
    return f"{int(mbit)}M" if mbit > 0 else ""


def _port_label(port, speed=0):
    parts = []
    if port:
        parts.append(f"Port {int(port)}")
    if _speed(speed):
        parts.append(_speed(speed))
    return " · ".join(parts)


class _Graph:
    def __init__(self):
        self.nodes, self.order, self.edges, self.by_ip, self.by_mac = {}, [], [], {}, {}

    def add(self, n):
        if n["id"] in self.nodes:
            return self.nodes[n["id"]]
        self.nodes[n["id"]] = n
        self.order.append(n["id"])
        if n.get("mac"):
            self.by_mac.setdefault(n["mac"], n["id"])
        if n.get("ip") and n.get("kind") != "vlan":
            self.by_ip.setdefault(n["ip"], n["id"])
        return n

    def link(self, a, b, kind, label=""):
        if not a or not b or a == b or any(e["from"] == a and e["to"] == b for e in self.edges):
            return
        self.edges.append({"from": a, "to": b, "kind": kind, "label": label})

    def merge(self, old, new):
        o, n = self.nodes.get(old), self.nodes.get(new)
        if not o or not n or old == new:
            return
        for k in ("mac", "vlan", "model", "ip"):
            if not n.get(k) and o.get(k):
                n[k] = o[k]
        n["info"] = n.get("info", []) + o.get("info", [])
        for e in self.edges:
            if e["from"] == old:
                e["from"] = new
            if e["to"] == old:
                e["to"] = new
        del self.nodes[old]
        for m in (self.by_ip, self.by_mac):
            for k, v in list(m.items()):
                if v == old:
                    m[k] = new

    def has_uplink(self, nid):
        return any(e["to"] == nid and e["kind"] != "net" for e in self.edges)

    def find_label(self, label, kind):
        found = None
        for nid in self.order:
            n = self.nodes.get(nid)
            if n and (n["label"] or "").strip().lower() == label.strip().lower():
                if n["kind"] == kind:
                    return nid
                if found is None and n["kind"] != "vlan":
                    found = nid
        if found and self.nodes[found]["kind"] in ("client", "device"):
            self.nodes[found]["kind"] = kind
        return found


def _unifi_kind(t, model):
    t = (t or "").lower()
    if t in ("ugw", "udm", "uxg"):
        return "gateway"
    if t == "usw" or (model or "").upper().startswith("US"):
        return "switch"
    if t == "uap":
        return "ap"
    return "device"


def build_netmap():
    g, warnings = _Graph(), []

    # 1) UniFi-Infrastruktur mit Uplinks
    infra = []
    if unifi.enabled:
        try:
            unifi._devices()
            infra = list(unifi.dev_list)
        except Exception as e:
            warnings.append(f"UniFi: {e}")
        if state.get("unifi_error"):
            warnings.append("UniFi: " + state["unifi_error"])
    upstream = set()
    for d in infra:
        mac = norm_mac(d.get("mac"))
        if not mac:
            continue
        info = []
        if d.get("version"):
            info.append("Firmware " + str(d["version"]))
        if d.get("num_sta"):
            info.append(f"{d['num_sta']} Clients")
        g.add({"id": "mac:" + mac, "label": d.get("name") or d.get("model") or mac,
               "kind": _unifi_kind(d.get("type"), d.get("model")), "ip": d.get("ip") or "", "mac": mac,
               "model": d.get("model") or "", "status": "up" if d.get("state") == 1 else "down",
               "source": "unifi", "info": info})
    for d in infra:
        mac, up = norm_mac(d.get("mac")), d.get("uplink") or {}
        upmac = norm_mac(up.get("uplink_mac"))
        if not mac or not upmac or upmac == mac:
            continue
        upstream.add(upmac)
        wifi = up.get("type") == "wireless"
        if "mac:" + upmac not in g.nodes:
            g.add({"id": "mac:" + upmac, "label": "Uplink " + upmac, "kind": "router", "mac": upmac, "source": "unifi"})
        g.link("mac:" + upmac, "mac:" + mac, "wifi" if wifi else "wire",
               "Mesh" if wifi else _port_label(up.get("uplink_remote_port"), up.get("speed")))

    # 2) alle erkannten Geräte, pro MAC der aktuellste Eintrag
    devs = list_devices()
    best = {}
    for d in devs:
        mac = d["mac"]
        b = best.get(mac)
        if not b or (d["online"], d["last_seen"] or 0) > (b["online"], b["last_seen"] or 0):
            best[mac] = d
    for mac, d in sorted(best.items(), key=lambda x: ip_sort_key(x[1]["ip"])):
        nid = "mac:" + mac
        info = []
        if d.get("vendor"):
            info.append("Hersteller: " + d["vendor"])
        if d.get("conn"):
            info.append(d["conn"])
        if nid in g.nodes:                     # Switch/AP aus UniFi: nur ergänzen
            n = g.nodes[nid]
            if d.get("name") or n["label"].startswith("Uplink "):
                n["label"] = display_name(d)
            if not n.get("ip") and d.get("ip"):
                n["ip"] = d["ip"]
                g.by_ip.setdefault(d["ip"], nid)
            n["vlan"] = vlan_label(d["vlan"])
            n["dev_id"] = d["id"]
            n["info"] = n.get("info", []) + info
            if mac in upstream:
                n["status"] = "up" if d["online"] else "down"
            continue
        name = display_name(d)
        g.add({"id": nid, "label": name, "kind": guess_kind(name, d.get("hostname"), d.get("vendor")),
               "ip": d.get("ip") or "", "mac": mac, "vlan": vlan_label(d["vlan"]), "status": "up" if d["online"] else "down",
               "source": "netwatch", "info": info, "dev_id": d["id"]})

    # 3) Verbindungen: erst strukturiert aus dem letzten Scan, sonst aus dem Text („🔌 Switch Port 3“)
    for mac, d in best.items():
        nid = "mac:" + mac
        if mac in upstream or g.has_uplink(nid):
            continue
        l = uni_links.get(mac)
        if l:
            if l.get("wired") and "mac:" + l.get("sw_mac", "") in g.nodes:
                g.link("mac:" + l["sw_mac"], nid, "wire", _port_label(l.get("sw_port")))
                continue
            if not l.get("wired") and "mac:" + l.get("ap_mac", "") in g.nodes:
                g.link("mac:" + l["ap_mac"], nid, "wifi", l.get("essid") or "")
                continue
        m = CONN_RE.match(d.get("conn") or "")
        if not m:
            continue
        if m.group(1):
            sw = g.find_label(m.group(1), "switch")
            if not sw:
                sw = "sw:" + m.group(1).lower()
                g.add({"id": sw, "label": m.group(1), "kind": "switch", "source": "netwatch"})
            g.link(sw, nid, "wire", f"Port {m.group(2)}" if m.group(2) else "")
        elif m.group(4):
            ap = g.find_label(m.group(4), "ap")
            if not ap:
                ap = "ap:" + m.group(4).lower()
                g.add({"id": ap, "label": m.group(4), "kind": "ap", "source": "netwatch"})
            g.link(ap, nid, "wifi", m.group(3) or "")

    # 4) VLANs als Netz-Knoten am Gateway (.1); Geräte ohne bekannte Verbindung hängen an ihrem VLAN
    used = sorted({d["vlan"] for d in best.values() if d["vlan"]})
    gw_for, gw_by_name = {}, {}
    for d in devs:
        v = d["vlan"]
        if not v or d["ip"] != f"{SUBNET_PREFIX}.{v}.1":
            continue
        nid = g.by_mac.get(d["mac"])
        if not nid:
            continue
        key = (d.get("name") or d.get("hostname") or "").strip().lower() or nid
        first = gw_by_name.get(key)
        if first and first != nid:
            g.merge(nid, first)          # OPNsense mit eigener MAC je VLAN → ein Gerät
            nid = first
        else:
            gw_by_name[key] = nid
        gw_for[v] = nid
        n = g.nodes.get(nid)
        if n and n["kind"] in ("client", "device", "router"):
            n["kind"] = "gateway"
    for v in used:
        vid = f"vlan:{v}"
        g.add({"id": vid, "label": vlan_label(v), "kind": "vlan", "ip": f"{SUBNET_PREFIX}.{v}.0/24", "source": "netwatch"})
        if gw_for.get(v) in g.nodes:
            g.link(gw_for[v], vid, "net")
    for mac, d in best.items():
        nid = g.by_mac.get(mac)
        n = g.nodes.get(nid)
        if not n or not d["vlan"] or g.has_uplink(nid) or n["kind"] in ("gateway", "vlan"):
            continue
        if any(e["from"] == nid and e["to"].startswith("vlan:") for e in g.edges):
            continue
        g.link(f"vlan:{d['vlan']}", nid, "net")
    for nid in list(g.order):              # Switches/APs ohne Uplink an ihr VLAN
        n = g.nodes.get(nid)
        if not n or n["kind"] not in ("switch", "ap") or g.has_uplink(nid) or not n.get("ip"):
            continue
        v = vlan_of(n["ip"])
        if v and v in used:
            g.link(f"vlan:{v}", nid, "net")

    nodes = [g.nodes[i] for i in g.order if i in g.nodes]
    edges, seen = [], set()
    for e in g.edges:
        if e["from"] not in g.nodes or e["to"] not in g.nodes or e["from"] == e["to"]:
            continue
        e["id"] = f"a:{e['from']}>{e['to']}"
        if e["id"] not in seen:
            seen.add(e["id"])
            edges.append(e)
    edges.sort(key=lambda e: e["id"])
    return {"nodes": nodes, "edges": edges, "warnings": warnings, "unifi": unifi.enabled,
            "map": netmap_load(), "updated": int(time.time())}


def netmap_load():
    try:
        d = json.loads(kv_get("netmap", "") or "{}")
    except Exception:
        d = {}
    if not isinstance(d, dict):
        d = {}
    out = {"pos": {}, "nodes": [], "edges": [], "hide_nodes": [], "hide_edges": [], "names": {}, "kinds": {}, "notes": {}}
    for k, v in out.items():
        if isinstance(d.get(k), type(v)):
            out[k] = d[k]
    return out


def netmap_save(data):
    if not isinstance(data, dict):
        raise ValueError("Netzplan ungültig")
    s = lambda v, n=300: str(v)[:n] if v is not None else ""
    pos = {}
    for k, v in (data.get("pos") or {}).items():
        try:
            pos[s(k, 200)] = [round(float(v[0]), 1), round(float(v[1]), 1)]
        except (TypeError, ValueError, IndexError):
            pass

    def items(lst, keys):
        out = []
        for it in lst or []:
            if isinstance(it, dict) and it.get("id"):
                m = {"id": s(it["id"], 200)}
                m.update({k: s(it[k]) for k in keys if it.get(k)})
                out.append(m)
        return out

    def strmap(m):
        return {s(k, 200): s(v) for k, v in (m or {}).items() if v} if isinstance(m, dict) else {}

    doc = {
        "pos": pos,
        "nodes": items(data.get("nodes"), ("label", "kind", "ip", "note")),
        "edges": items(data.get("edges"), ("from", "to", "kind", "label")),
        "hide_nodes": [s(x, 200) for x in data.get("hide_nodes") or []],
        "hide_edges": [s(x, 400) for x in data.get("hide_edges") or []],
        "names": strmap(data.get("names")), "kinds": strmap(data.get("kinds")), "notes": strmap(data.get("notes")),
    }
    if len(doc["nodes"]) > 1000 or len(doc["edges"]) > 3000 or len(pos) > 5000:
        raise ValueError("Netzplan zu groß")
    with netmap_lock:
        kv_set("netmap", json.dumps(doc, ensure_ascii=False))


class Handler(BaseHTTPRequestHandler):
    server_version = "NetWatch"

    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _auth(self):
        if not WEB_PASSWORD:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                if secrets.compare_digest(u, WEB_USER) and secrets.compare_digest(p, WEB_PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="NetWatch"')
        self.end_headers()
        return False

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    def do_GET(self):
        if not self._auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
                return self._send(200, f.read(), "text/html")
        if path == "/api/state":
            return self._send(200, api_state())
        if path == "/api/events":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, api_events(qs))
        if path == "/api/traffic":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, api_traffic(qs))
        if path.startswith("/api/devices/") and path.endswith("/traffic"):
            try:
                dev_id = int(path.split("/")[3])
            except (ValueError, IndexError):
                return self._send(400, {"error": "bad id"})
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, api_device_traffic(dev_id, qs))
        if path == "/api/netmap":
            return self._send(200, build_netmap())
        if path == "/health":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/scan":
            threading.Thread(target=scan_once, daemon=True).start()
            return self._send(200, {"ok": True})
        if path == "/api/telegram/test":
            ok, err = tg_send_now("✅ NetWatch Test-Nachricht – Telegram funktioniert.")
            add_event(None, "info", "Telegram-Test " + ("erfolgreich" if ok else "fehlgeschlagen"),
                      "sent" if ok else f"error: {err}")
            return self._send(200 if ok else 500, {"ok": ok, "error": err})
        if path == "/api/netmap":
            try:
                netmap_save(self._body())
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            return self._send(200, {"ok": True})
        if path.startswith("/api/devices/"):
            return self._update(path)
        self._send(404, {"error": "not found"})

    def _update(self, path):
        if path.endswith("/check"):
            try:
                dev_id = int(path.split("/")[3])
            except (ValueError, IndexError):
                return self._send(400, {"error": "bad id"})
            with db_lock:
                r = db().execute("SELECT ip FROM devices WHERE id=?", (dev_id,)).fetchone()
            if not r or not r["ip"]:
                return self._send(404, {"error": "not found"})
            return self._send(200, {"ok": True, "alive": ping(r["ip"]), "ip": r["ip"]})
        try:
            dev_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            return self._send(400, {"error": "bad id"})
        data = self._body()
        fields = {}
        if "name" in data:
            fields["name"] = str(data["name"])[:80].strip()
        if "watch" in data:
            fields["watch"] = 1 if data["watch"] else 0
        if "traffic_limit" in data:      # MB/s; null/"" = Standard, 0 = aus
            v = data["traffic_limit"]
            if v is None or str(v).strip() == "":
                fields["traffic_limit"] = None
            else:
                try:
                    fields["traffic_limit"] = max(0.0, float(str(v).replace(",", ".")))
                except ValueError:
                    return self._send(400, {"error": "traffic_limit muss eine Zahl sein"})
        if not fields:
            return self._send(400, {"error": "nothing to update"})
        with db_lock:
            sets = ",".join(f"{k}=?" for k in fields)
            db().execute(f"UPDATE devices SET {sets} WHERE id=?", (*fields.values(), dev_id))
            db().commit()
        self._send(200, {"ok": True})

    def do_DELETE(self):
        if not self._auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/events":
            with db_lock:
                db().execute("DELETE FROM events")
                db().commit()
            return self._send(200, {"ok": True})
        if path.startswith("/api/devices/"):
            try:
                dev_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            with db_lock:
                db().execute("DELETE FROM devices WHERE id=?", (dev_id,))
                db().execute("DELETE FROM traffic_hourly WHERE device=?", (dev_id,))
                db().execute("DELETE FROM traffic_daily WHERE device=?", (dev_id,))
                db().commit()
            live_rates.pop(dev_id, None)
            alert_state.pop(dev_id, None)
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})


def main():
    db()
    if not OPN_KEY or not OPN_SECRET:
        log.warning("OPNSENSE_KEY / OPNSENSE_SECRET fehlen – Scans werden fehlschlagen.")
    threading.Thread(target=tg_worker, daemon=True).start()
    if TG_TOKEN and TG_CHAT:
        log.info("Telegram aktiv (Chat %s, neue Geräte melden: %s)", TG_CHAT, NOTIFY_NEW)
    else:
        log.warning("Telegram NICHT konfiguriert – TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID fehlen")
    threading.Thread(target=scanner_loop, daemon=True).start()
    if TG_TOKEN and TG_CHAT and TG_COMMANDS:
        threading.Thread(target=tg_bot_loop, daemon=True).start()
    if TRAFFIC_ENABLED:
        threading.Thread(target=traffic_loop, daemon=True).start()
        log.info("Traffic-Erfassung aktiv (alle %d s, Insight: %s, Alarm: %s)", TRAFFIC_INTERVAL, TRAFFIC_INSIGHT,
                 f"> {TRAFFIC_ALERT_MBS:g} MB/s für {TRAFFIC_ALERT_MINUTES} min" if TRAFFIC_ALERT_MBS > 0 else "aus")
    log.info("NetWatch läuft auf Port %d (VLANs: %s)", WEB_PORT, ",".join(map(str, VLANS)))
    ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()

# NetWatch – Geräteübersicht für OPNsense (+ UniFi) mit Telegram

Ein kleiner NetAlertX-Ersatz:

- liest ARP-Tabelle + DHCP-Leases (ISC, Kea oder Dnsmasq) aus der **OPNsense-API**
- optional verbundene Clients aus **UniFi OS** (Aliasname, SSID/AP oder Switch-Port, Signal)
- sortiert Geräte nach VLAN: `192.168.10.x` → VLAN 10 … `192.168.90.x` → VLAN 90
- Web-UI: Geräte benennen, Online-Status, Suche, Filter
- eigene Seite **Ereignisse** (`#/events`): neu / online / offline / IP geändert, filterbar, mit Telegram-Zustellstatus (✓ / ✕)
- **Telegram**: Nachricht bei neuem Gerät (mit dem Namen, den das Gerät meldet), Online/Offline-Meldungen für markierte Geräte (🔔)
- **Telegram-Befehle**: `/check NAME`, `/online [vlan]`, `/offline [vlan]`, `/status`, `/scan`, `/traffic NAME`, `/top`
- **Netzplan** (`#/net`): alle erkannten Geräte als Plan mit Verkabelung – Gateway → VLANs → Switches/APs → Geräte,
  Switch-Ports und WLAN aus UniFi; eigene Geräte und Kabel dazuzeichnen
- **Traffic pro Gerät**: live ↑/↓ in der Geräteliste, Verlauf (24 h / 7 Tage / 30 Tage) in der Detailansicht, Seite **Traffic** (`#/traffic`) mit Top-Verbrauchern pro Gerät und VLAN, optional Telegram-Alarm bei Dauerlast

Geschrieben in **Go** (ein einzelnes statisches Binary, SQLite in reinem Go eingebaut, kein CGO). Das Web-UI (`app/index.html`) wird ins Binary eingebettet.

## 1. OPNsense-API-Schlüssel

1. *System → Zugang → Benutzer* → neuen Benutzer `netwatch` anlegen (kein Login nötig).
2. Rechte (*Effektive Rechte*) mindestens:
   - `Diagnostics: ARP Table`
   - je nach DHCP-Dienst: `Services: DHCP: Kea(v4)`, `Status: DHCP leases` (ISC) oder `Services: Dnsmasq DNS/DHCP`
   - für Traffic: `Reporting: Traffic` (ältere Versionen: `Diagnostics: Traffic Graph`)
   - optional für den Verlauf aus Insight: `Reporting: Insight` (ältere Versionen: `Diagnostics: Network Insight`) und `Diagnostics: Netflow configuration` (nur für die Prüfung, ob Netflow aktiv ist)

   Fehlt ein Recht, zeigt NetWatch oben im UI und auf der Traffic-Seite genau an, welches.
3. Beim Benutzer unter *API-Schlüssel* auf **+** → Datei mit `key` und `secret` wird heruntergeladen.

## 2. UniFi (optional)

Im UniFi-Controller einen **lokalen** Benutzer anlegen (*Admins & Users* → Admin hinzufügen → „Restrict to local access only“, Rolle *View Only* reicht).
UDM / Cloud Key Gen2+ / UniFi OS Server: `UNIFI_IS_UNIFI_OS=true`. Klassischer Controller (Port 8443): `false`.

Vorteil: Handys im WLAN antworten oft nicht auf Ping – UniFi weiß trotzdem, dass sie verbunden sind.

## 3. Telegram-Bot

1. In Telegram **@BotFather** → `/newbot` → Token kopieren.
2. Dem neuen Bot einmal eine Nachricht schicken.
3. Chat-ID holen: `https://api.telegram.org/bot<TOKEN>/getUpdates` im Browser öffnen → `"chat":{"id":123456789…}`.
   (Für eine Gruppe: Bot zur Gruppe hinzufügen, die ID beginnt dann mit `-`.)

Der Bot reagiert nur auf Nachrichten aus dieser Chat-ID.

Beim **allerersten Scan** kommt eine Zusammenfassung („X Geräte erfasst“) statt einer Nachricht pro Gerät. Danach meldet jedes neue Gerät einzeln. Ob eine Nachricht rausging, siehst du auf der Ereignisseite in der Spalte ✈︎. Fehler von Telegram stehen oben im UI und im Log (`docker compose logs`).

## 4. Starten

```bash
cp .env.example .env     # Werte eintragen
docker compose up -d --build
```

Web-UI: `http://<docker-host>:8080`

### Update von der Python-Version

Datenbank und `.env` bleiben gleich – einfach neu bauen:

```bash
git pull
docker compose up -d --build
```

Gerätenamen, Ereignisse, Traffic-Verlauf und Netzplan aus `data/netwatch.db` werden übernommen.

### Ohne Docker

```bash
CGO_ENABLED=0 go build -o netwatch .     # Go ≥ 1.24
set -a; . ./.env; set +a
DB_PATH=./data/netwatch.db ./netwatch
```

Für die Online-Prüfung per Ping muss `ping` installiert sein (bzw. `ONLINE_MODE=arp`).

## Traffic

NetWatch fragt alle `TRAFFIC_INTERVAL` Sekunden (Standard 30) die **Top Talker** der OPNsense ab (`/api/diagnostics/traffic/top/<interfaces>`, dieselben Daten wie *Reporting → Traffic → Top Talkers*) und ordnet die Raten den Geräten per IP zu. Abgefragt werden automatisch alle Interfaces, an denen laut ARP-Tabelle Geräte hängen (also deine VLANs, nicht WAN) – oder fest die in `TRAFFIC_INTERFACES` (z. B. `lan,opt1,opt2`, Schlüssel wie unter *Schnittstellen → Zuweisungen*).

- **Live**: ↓ Download / ↑ Upload je Gerät in der Geräteliste und in der Detailansicht.
- **Verlauf**: Aus den Raten werden Bytes hochgerechnet (Rate × Zeit) und pro Gerät und Stunde bzw. Tag in SQLite gespeichert. Das ist eine Schätzung – kurze Spitzen zwischen zwei Abfragen fehlen, und Top Talker listet nur die aktivsten Adressen.
- **Insight / Netflow (optional, genauer)**: Ist unter *Reporting → NetFlow* die lokale Erfassung („Capture local“) für die VLAN-Interfaces aktiv, übernimmt NetWatch alle 10 Minuten abgeschlossene Stunden aus Insight (`/api/diagnostics/networkinsight/top/FlowSourceAddrTotals/…`) und ersetzt damit die hochgerechneten Werte. Beim ersten Start werden die letzten `TRAFFIC_INSIGHT_BACKFILL_HOURS` Stunden nachgeladen. `TRAFFIC_INSIGHT=false` schaltet das ab.
- **Aufbewahrung**: Stundenwerte `TRAFFIC_HOURLY_DAYS` Tage (Standard 31), Tageswerte `TRAFFIC_DAILY_DAYS` Tage (Standard 365).
- **Alarm**: Für Geräte mit 🔔 kommt eine Telegram-Nachricht, wenn sie länger als `TRAFFIC_ALERT_MINUTES` über `TRAFFIC_ALERT_MBS` MB/s liegen (z. B. 5 MB/s für 10 min), und eine Entwarnung, wenn es vorbei ist. In der Detailansicht lässt sich pro Gerät ein eigener Wert setzen (leer = Standard, `0` = aus). `TRAFFIC_ALERT_DIRECTION` = `total` (↑+↓), `down` oder `up`.
- **Telegram**: `/traffic NAME` (live, heute, 24 h, 7 Tage, 30 Tage), `/top` (jetzt + letzte 24 h), `/top 7d`, `/top 30d`, `/top live`, mit VLAN-Nummer gefiltert z. B. `/top 24h 20`.

> **Wichtig:** Die Firewall sieht nur Verkehr, der **über sie** läuft – ins Internet und zwischen VLANs. Verkehr zwischen zwei Geräten im **selben** VLAN (z. B. PC ↔ NAS im gleichen Netz) geht direkt über den Switch und taucht in NetWatch nicht auf.

Verkehr zwischen zwei VLANs sieht die Firewall auf beiden VLAN-Interfaces; NetWatch zählt ihn pro Gerät nur einmal (vom Interface, an dem das Gerät laut ARP hängt). Wirken ↑ und ↓ vertauscht, `TRAFFIC_SWAP_DIRECTION=true` setzen.

## Netzplan

Der Reiter **Netz** baut den Plan automatisch:

- **Geräte**: alle erkannten Geräte (pro MAC der aktuellste Eintrag), mit Online-Status. Der Typ (Handy, Smart Home, TV,
  Drucker, NAS, Switch, AP …) wird aus Name/Hersteller geraten und lässt sich ändern
- **Mit UniFi**: Switches und APs samt Uplinks (Port, Geschwindigkeit, Mesh), Geräte am Switch-Port bzw. per WLAN am AP.
  Das Gerät über dem obersten Switch (z. B. die OPNsense) erscheint als Uplink
- **VLANs**: jedes VLAN ist ein Knoten am Gateway (das Gerät mit `.1`; hat die OPNsense je VLAN eine eigene MAC, wird sie
  zu einem Gerät zusammengelegt). Geräte ohne bekannte Verbindung hängen an ihrem VLAN

**Bedienen:** Fläche ziehen = verschieben, Mausrad/zwei Finger = zoomen, ⤢ = alles anzeigen. Gerät antippen zeigt IP, MAC,
Netz und Verbindungen; Name, Typ und Notiz ändern, ausblenden oder **Details** (normale Geräteansicht). **✎ Bearbeiten**
schaltet frei: Geräte ziehen, **+ Gerät** (z. B. Vodafone Station, Patchfeld), **⤳ Kabel ziehen** (Start- und Zielgerät
antippen, Art und Beschriftung wie „Port 3 ↔ eth0“) und **Auto-Anordnen**. Selbst gezeichnete Kabel sind gelb.
„Clients“ und „Offline“ blenden Endgeräte bzw. offline Geräte aus. Alles wird in der Datenbank gespeichert (`kv` → `netmap`).

API: `GET /api/netmap` (Plan + gespeicherte Ergänzungen), `POST /api/netmap` (Ergänzungen speichern).

## Online-Erkennung

Ein Gerät gilt als online, wenn es **auf Ping antwortet**, **in der ARP-Tabelle aktiv ist** oder **in UniFi verbunden ist** (`ONLINE_MODE=ping_or_arp`).
Offline wird erst nach `OFFLINE_AFTER_CHECKS` Fehlversuchen gemeldet (verhindert Fehlalarme).

Hinweise:

- Der Container läuft im `host`-Netz und pingt von dort in alle VLANs. Die **Firewall-Regeln** müssen ICMP vom Docker-Host in die anderen VLANs erlauben.
- OPNsense hält ARP-Einträge standardmäßig 20 Minuten. Für schnellere Offline-Erkennung unter *System → Einstellungen → Tunables* `net.link.ether.inet.max_age` z. B. auf `300` setzen.
- `/check NAME` pingt das Gerät **live**. 🟡 heißt: kein Ping, aber Firewall/UniFi sieht es noch.

## Wie Geräte gespeichert werden

Ein Gerät ist **MAC + VLAN**. Wechselt die IP per DHCP, bleibt der Name erhalten (bei markierten Geräten kommt eine Telegram-Meldung „IP geändert“).
**WLAN-/VLAN-Wechsel und private MAC-Adressen:** Taucht ein Gerät in einem anderen VLAN auf (z. B. zweites WLAN) oder mit einer neuen privaten MAC (iOS/Android verwenden pro WLAN eine eigene), wird es dem bestehenden Eintrag zugeordnet – wenn die MAC gleich ist oder bei privater MAC der Hostname übereinstimmt und der alte Eintrag gerade nicht aktiv ist. Name und 🔔 bleiben erhalten, es kommt keine „Neues Gerät“-Meldung. Beobachtete Geräte melden stattdessen „Wechselt WLAN/VLAN“.

Geräte mit privater MAC **ohne** Hostname lassen sich nicht sicher zuordnen. Für eigene Geräte in den WLAN-Einstellungen „Private WLAN-Adresse“ auf **Aus** oder **Fest** (nicht „Rotierend“) stellen.

`MERGE_RANDOM_MAC=false` schaltet die Zuordnung per Hostname ab, `NOTIFY_RANDOM_MAC=false` unterdrückt „Neues Gerät“-Meldungen für Geräte mit privater MAC.

Daten liegen in `./data/netwatch.db` (SQLite).

## Alle Einstellungen

| Variable | Standard | Bedeutung |
|---|---|---|
| `OPNSENSE_URL` | `https://192.168.10.1` | Adresse der OPNsense |
| `OPNSENSE_KEY` / `OPNSENSE_SECRET` | – | API-Zugang |
| `OPNSENSE_VERIFY_SSL` | `false` | Zertifikat prüfen |
| `SUBNET_PREFIX` | `192.168` | erste zwei Oktette |
| `VLANS` | `10,20,…,90` | drittes Oktett = VLAN |
| `VLAN_NAMES` | – | z. B. `10:Management,40:IoT` |
| `SCAN_INTERVAL` | `60` | Sekunden zwischen Scans |
| `ONLINE_MODE` | `ping_or_arp` | `ping_or_arp`, `ping` oder `arp` (UniFi zählt immer zusätzlich) |
| `OFFLINE_AFTER_CHECKS` | `3` | Fehlversuche bis offline |
| `INCLUDE_FIREWALL` | `false` | eigene Interfaces der OPNsense anzeigen |
| `UNIFI_URL` | – | z. B. `https://192.168.10.2` (leer = aus) |
| `UNIFI_USER` / `UNIFI_PASSWORD` | – | lokaler UniFi-Benutzer |
| `UNIFI_SITE` | `default` | Site-ID |
| `UNIFI_IS_UNIFI_OS` | `true` | UniFi OS oder klassischer Controller |
| `UNIFI_USE_NAMES` | `true` | Aliasnamen aus UniFi als Anzeigename |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | – | Telegram |
| `NOTIFY_NEW_DEVICES` | `true` | Meldung bei neuem Gerät |
| `WATCH_NEW_DEVICES` | `false` | neue Geräte automatisch 🔔 beobachten |
| `TELEGRAM_COMMANDS` | `true` | Bot-Befehle aktivieren |
| `TRAFFIC_ENABLED` | `true` | Traffic-Erfassung an/aus |
| `TRAFFIC_INTERVAL` | `30` | Sekunden zwischen Top-Talker-Abfragen (min. 10) |
| `TRAFFIC_INTERFACES` | – | feste Interface-Liste, z. B. `lan,opt1,opt2` (leer = automatisch) |
| `TRAFFIC_SWAP_DIRECTION` | `false` | ↑/↓ vertauschen |
| `TRAFFIC_INSIGHT` | `auto` | Verlauf aus Insight: `auto`, `true`, `false` |
| `TRAFFIC_INSIGHT_BACKFILL_HOURS` | `24` | so viele Stunden beim ersten Start aus Insight nachladen |
| `TRAFFIC_HOURLY_DAYS` | `31` | Stundenwerte aufbewahren (Tage, min. 8) |
| `TRAFFIC_DAILY_DAYS` | `365` | Tageswerte aufbewahren (Tage, min. 31) |
| `TRAFFIC_ALERT_MBS` | `0` | Alarm-Schwelle in MB/s für 🔔-Geräte (0 = aus) |
| `TRAFFIC_ALERT_MINUTES` | `10` | so lange muss die Schwelle überschritten sein |
| `TRAFFIC_ALERT_DIRECTION` | `total` | `total`, `down` oder `up` |
| `WEB_PORT` | `8080` | Port des Web-UI |
| `WEB_USER` / `WEB_PASSWORD` | `admin` / leer | Login fürs Web-UI (leer = ohne) |

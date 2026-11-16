package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// UniFi (optional): verbundene Clients und Infrastruktur (UniFi OS oder klassisch)
// --------------------------------------------------------------------------

type uniClient struct {
	IP, Name, Hostname, Conn, Vendor string
	Wired                            bool
	SwMAC                            string
	SwPort                           int
	ApMAC, Essid                     string
}

type UniFi struct {
	mu        sync.Mutex
	client    *http.Client
	cookies   map[string]string
	csrf      string
	base      string
	apNames   map[string]string
	apNamesTS time.Time
	devList   []map[string]any // stat/device komplett (Switches/APs mit Uplink) für den Netzplan
}

var unifi = &UniFi{
	client:  newClient(unifiVerifySSL, false),
	cookies: map[string]string{},
	base:    unifiURL + map[bool]string{true: "/proxy/network", false: ""}[unifiIsOS],
	apNames: map[string]string{},
}

func (u *UniFi) enabled() bool { return unifiURL != "" && unifiUser != "" && unifiPassword != "" }

func (u *UniFi) open(url string, payload any) (any, error) {
	h := map[string]string{"Accept": "application/json"}
	if len(u.cookies) > 0 {
		var parts []string
		for k, v := range u.cookies {
			parts = append(parts, k+"="+v)
		}
		h["Cookie"] = strings.Join(parts, "; ")
	}
	if u.csrf != "" {
		h["X-CSRF-Token"] = u.csrf
	}
	method := "GET"
	if payload != nil {
		method = "POST"
	}
	res, resp, err := doJSON(u.client, method, url, h, payload, 20*time.Second)
	if resp != nil {
		for _, c := range resp.Header.Values("Set-Cookie") {
			k, rest, _ := strings.Cut(c, "=")
			v, _, _ := strings.Cut(rest, ";")
			u.cookies[strings.TrimSpace(k)] = v
		}
		if tok := firstNonEmpty(resp.Header.Get("X-CSRF-Token"), resp.Header.Get("X-Updated-CSRF-Token")); tok != "" {
			u.csrf = tok
		}
	}
	return res, err
}

func (u *UniFi) login() error {
	u.cookies, u.csrf = map[string]string{}, ""
	path := "/api/login"
	if unifiIsOS {
		path = "/api/auth/login"
	}
	_, err := u.open(unifiURL+path, map[string]any{"username": unifiUser, "password": unifiPassword, "remember": true})
	return err
}

func (u *UniFi) get(path string) (any, error) {
	url := fmt.Sprintf("%s/api/s/%s/%s", u.base, unifiSite, path)
	if len(u.cookies) == 0 {
		if err := u.login(); err != nil {
			return nil, err
		}
	}
	res, err := u.open(url, nil)
	var he *httpError
	if errors.As(err, &he) && (he.Code == 401 || he.Code == 403) {
		if err := u.login(); err != nil {
			return nil, err
		}
		return u.open(url, nil)
	}
	return res, err
}

// devices aktualisiert alle 10 Minuten stat/device und liefert MAC -> Name.
func (u *UniFi) devices() map[string]string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.devicesLocked()
}

func (u *UniFi) devicesLocked() map[string]string {
	if time.Since(u.apNamesTS) > 600*time.Second {
		res, err := u.get("stat/device")
		if err != nil {
			logDebug("UniFi stat/device: %v", err)
		} else {
			u.devList = mapsOf(asMap(res)["data"])
			u.apNames = map[string]string{}
			for _, d := range u.devList {
				u.apNames[normMAC(d["mac"])] = gs(d, "name", "model")
			}
			u.apNamesTS = time.Now()
		}
	}
	return u.apNames
}

// deviceList: Kopie von stat/device (für den Netzplan).
func (u *UniFi) deviceList() []map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.devicesLocked()
	return append([]map[string]any(nil), u.devList...)
}

// clients: mac -> Client. Nur aktuell verbundene Clients.
func (u *UniFi) clients() (map[string]uniClient, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	res, err := u.get("stat/sta")
	if err != nil {
		return nil, err
	}
	names := u.devicesLocked()
	out := map[string]uniClient{}
	now := float64(time.Now().Unix())
	for _, c := range mapsOf(asMap(res)["data"]) {
		mac := normMAC(c["mac"])
		ip := gs(c, "ip", "last_ip")
		if mac == "" {
			continue
		}
		if ls := num(c["last_seen"]); ls != 0 && now-ls > 300 {
			continue
		}
		var conn string
		wired := truthy(c["is_wired"])
		if wired {
			sw := firstNonEmpty(names[normMAC(c["sw_mac"])], "Switch")
			conn = "🔌 " + sw
			if truthy(c["sw_port"]) {
				conn += " Port " + pyStr(c["sw_port"])
			}
		} else {
			ap := firstNonEmpty(names[normMAC(c["ap_mac"])], "AP")
			conn = fmt.Sprintf("📶 %s @ %s", gs(c, "essid"), ap)
			if truthy(c["signal"]) {
				conn += fmt.Sprintf(" (%s dBm)", pyStr(c["signal"]))
			}
		}
		out[mac] = uniClient{
			IP: ip, Name: gs(c, "name"), Hostname: gs(c, "hostname"), Conn: strings.TrimSpace(conn),
			Vendor: gs(c, "oui"), Wired: wired, SwMAC: normMAC(c["sw_mac"]), SwPort: int(num(c["sw_port"])),
			ApMAC: normMAC(c["ap_mac"]), Essid: gs(c, "essid"),
		}
	}
	return out, nil
}

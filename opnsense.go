package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// OPNsense API
// --------------------------------------------------------------------------

type httpError struct {
	Code int
	Body []byte
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP Error %d", e.Code) }

// apiPermissionError: dem API-Benutzer fehlt ein Recht (403).
type apiPermissionError struct{ msg string }

func (e *apiPermissionError) Error() string { return e.msg }

// netError: Gegenstelle nicht erreichbar (DNS, Verbindung, Timeout, TLS).
type netError struct{ err error }

func (e *netError) Error() string { return e.err.Error() }

func newClient(verify bool, useProxy bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !verify},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	if useProxy {
		tr.Proxy = http.ProxyFromEnvironment
	} // sonst: Proxy-Variablen für das lokale Netz ignorieren
	return &http.Client{Transport: tr}
}

// doJSON schickt GET (payload nil) oder POST mit JSON und dekodiert die Antwort.
func doJSON(c *http.Client, method, u string, headers map[string]string, payload any, timeout time.Duration) (any, *http.Response, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cl := *c
	cl.Timeout = timeout
	resp, err := cl.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, nil, &netError{ue.Err}
		}
		return nil, nil, &netError{err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, &netError{err}
	}
	if resp.StatusCode >= 400 {
		return nil, resp, &httpError{Code: resp.StatusCode, Body: data}
	}
	var out any
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, resp, nil
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, resp, fmt.Errorf("ungültige JSON-Antwort: %v", err)
	}
	return out, resp, nil
}

const (
	rightTraffic = "„Reporting: Traffic“ (ältere Versionen: „Diagnostics: Traffic Graph“)"
	rightInsight = "„Reporting: Insight“ (ältere Versionen: „Diagnostics: Network Insight“)"
)

type OPNsense struct {
	client        *http.Client
	headers       map[string]string
	mu            sync.Mutex
	leaseEndpoint string // wird beim ersten erfolgreichen Abruf gemerkt
}

var opn = newOPNsense()

func newOPNsense() *OPNsense {
	token := base64.StdEncoding.EncodeToString([]byte(opnKey + ":" + opnSecret))
	return &OPNsense{
		client:  newClient(opnVerifySSL, false),
		headers: map[string]string{"Authorization": "Basic " + token, "Accept": "application/json"},
	}
}

func (o *OPNsense) req(path string, payload any, timeout time.Duration) (any, error) {
	method := "GET"
	if payload != nil {
		method = "POST"
	}
	res, _, err := doJSON(o.client, method, opnURL+path, o.headers, payload, timeout)
	return res, err
}

func unreachable(err error) error {
	return fmt.Errorf("OPNsense nicht erreichbar unter %s: %v", opnURL, err)
}

// call: wie req, aber mit verständlichen Fehlermeldungen (401/403/nicht erreichbar).
func (o *OPNsense) call(path, right string, payload any, timeout time.Duration) (any, error) {
	res, err := o.req(path, payload, timeout)
	var he *httpError
	var ne *netError
	switch {
	case errors.As(err, &he) && he.Code == 401:
		return nil, errors.New("401 – API-Key/Secret falsch (OPNSENSE_KEY / OPNSENSE_SECRET prüfen)")
	case errors.As(err, &he) && he.Code == 403:
		return nil, &apiPermissionError{fmt.Sprintf("403 – dem API-Benutzer fehlt das Recht %s "+
			"(OPNsense: System → Zugang → Benutzer → Benutzer bearbeiten → Effektive Rechte)", right)}
	case errors.As(err, &ne):
		return nil, unreachable(ne)
	}
	return res, err
}

// ---- Traffic (Reporting → Traffic) ----

type ifInfo struct {
	Name   string
	Device string
}

// trafficInterfaces: Interface-Schlüssel (lan, opt1 …) -> {name, device}.
func (o *OPNsense) trafficInterfaces() (map[string]ifInfo, error) {
	res, err := o.call("/api/diagnostics/traffic/interface", rightTraffic, nil, 20*time.Second)
	if err != nil {
		return nil, err
	}
	m := asMap(res)
	if inner := asMap(m["interfaces"]); inner != nil {
		m = inner
	}
	out := map[string]ifInfo{}
	for k, v := range m {
		if vm := asMap(v); vm != nil {
			out[k] = ifInfo{Name: firstNonEmpty(gs(vm, "name"), k), Device: gs(vm, "device", "if")}
		}
	}
	return out, nil
}

// trafficTop: Top Talker der Interfaces (iftop auf der Firewall, dauert ein paar Sekunden).
func (o *OPNsense) trafficTop(keys []string) (map[string]any, error) {
	path := "/api/diagnostics/traffic/top/" + strings.ReplaceAll(url.PathEscape(strings.Join(keys, ",")), "%2C", ",")
	res, err := o.call(path, rightTraffic, nil, 90*time.Second)
	if err != nil {
		return nil, err
	}
	if m := asMap(res); m != nil {
		return m, nil
	}
	return map[string]any{}, nil
}

// ---- Insight / Netflow (optional) ----

// netflowEnabled: 1 = ja, 0 = nein, -1 = unbekannt (fehlendes Recht oder alte Version).
func (o *OPNsense) netflowEnabled() int {
	res, err := o.req("/api/diagnostics/netflow/isEnabled", nil, 20*time.Second)
	m := asMap(res)
	if err != nil || m == nil {
		return -1
	}
	v, ok := m["local"]
	if !ok {
		v = m["netflow"]
	}
	if s := strings.ToLower(pyStr(v)); s == "1" || s == "true" {
		return 1
	}
	return 0
}

// insightTop: Summen pro Quell-Adresse, Interface und Richtung im Zeitraum (Bytes).
func (o *OPNsense) insightTop(from, to int64) ([]map[string]any, error) {
	path := fmt.Sprintf("/api/diagnostics/networkinsight/top/FlowSourceAddrTotals/%d/%d/if,src_addr,direction/octets/2000", from, to)
	res, err := o.call(path, rightInsight, nil, 60*time.Second)
	if err != nil {
		return nil, err
	}
	return mapsOf(res), nil
}

// ---- ARP / DHCP ----

// arp: Liste mit mac, ip, intf, manufacturer, hostname, expired, permanent.
func (o *OPNsense) arp() ([]map[string]any, error) {
	rows, err := o.arpRaw()
	var he *httpError
	var ne *netError
	switch {
	case errors.As(err, &he) && he.Code == 401:
		return nil, errors.New("401 – API-Key/Secret falsch (OPNSENSE_KEY / OPNSENSE_SECRET prüfen)")
	case errors.As(err, &he) && he.Code == 403:
		return nil, errors.New("403 – API-Benutzer fehlt das Recht 'Diagnostics: ARP Table' " +
			"(System > Zugang > Benutzer > Effektive Rechte)")
	case errors.As(err, &ne):
		return nil, unreachable(ne)
	}
	return rows, err
}

func (o *OPNsense) arpRaw() ([]map[string]any, error) {
	res, err := o.req("/api/diagnostics/interface/getArp", nil, 20*time.Second)
	var he *httpError
	if err == nil {
		if l, ok := res.([]any); ok {
			return mapsOf(l), nil
		}
		if m := asMap(res); m != nil {
			if l, ok := m["rows"].([]any); ok {
				return mapsOf(l), nil
			}
		}
	} else if !(errors.As(err, &he) && (he.Code == 404 || he.Code == 400)) {
		return nil, err
	}
	// neuere Versionen: search_arp
	res, err = o.req("/api/diagnostics/interface/search_arp", map[string]any{"current": 1, "rowCount": -1}, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return mapsOf(asMap(res)["rows"]), nil
}

type lease struct {
	MAC, IP, Hostname string
}

// leases: DHCP-Leases (Dnsmasq, Kea oder ISC).
func (o *OPNsense) leases() []lease {
	candidates := []string{"/api/dnsmasq/leases/search", "/api/kea/leases4/search", "/api/dhcpv4/leases/searchLease"}
	o.mu.Lock()
	known := o.leaseEndpoint
	o.mu.Unlock()
	if known != "" {
		sorted := []string{known}
		for _, c := range candidates {
			if c != known {
				sorted = append(sorted, c)
			}
		}
		candidates = sorted
	}
	var out []lease
	for _, path := range candidates {
		res, err := o.req(path, map[string]any{"current": 1, "rowCount": -1, "searchPhrase": ""}, 20*time.Second)
		if err != nil {
			continue
		}
		rows := mapsOf(asMap(res)["rows"])
		if len(rows) == 0 {
			continue
		}
		o.mu.Lock()
		o.leaseEndpoint = path
		o.mu.Unlock()
		for _, r := range rows {
			mac := normMAC(firstNonEmpty(gs(r, "mac"), gs(r, "hwaddr"), gs(r, "hw_address")))
			ip := gs(r, "address", "ip", "ip_address")
			host := gs(r, "hostname", "client-hostname", "client_hostname")
			if mac != "" && ip != "" {
				out = append(out, lease{mac, ip, host})
			}
		}
		break
	}
	return out
}

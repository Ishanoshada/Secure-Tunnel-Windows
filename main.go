package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37

	GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100
	AF_UNSPEC                       = 0
	IfOperStatusUp                  = 1
	IF_TYPE_SOFTWARE_LOOPBACK       = 24
)

// ── Tool configuration (loaded from config.json) ──────────────────────────────

type ToolConfig struct {
	ExePath       string `json:"exePath"`
	LocalPort     int    `json:"localPort"`
	SNIHost       string `json:"sniHost"`
	ServerAddress string `json:"serverAddress"`
	ServerPort    int    `json:"serverPort"`
	UserID        string `json:"userID"`
	Path          string `json:"path"`
	TunnelName    string `json:"tunnelName"` // Optional custom tunnel name
}

var toolConfig ToolConfig
var tunnelDisplayName string

// ── Xray config structs ───────────────────────────────────────────────────────

type XrayConfig struct {
	Log       LogConfig        `json:"log"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Policy    PolicyConfig     `json:"policy"`
}
type LogConfig struct{ Loglevel string `json:"loglevel"` }
type InboundConfig struct {
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Sniffing SniffingConfig  `json:"sniffing"`
	Settings InboundSettings `json:"settings"`
}
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}
type InboundSettings struct {
	UDP  bool   `json:"udp"`
	Auth string `json:"auth"`
}
type OutboundConfig struct {
	Protocol       string           `json:"protocol"`
	Settings       OutboundSettings `json:"settings"`
	StreamSettings StreamSettings   `json:"streamSettings"`
	Mux            MuxConfig        `json:"mux"`
}
type OutboundSettings struct{ VNext []VNextConfig `json:"vnext"` }
type VNextConfig struct {
	Address string       `json:"address"`
	Port    int          `json:"port"`
	Users   []UserConfig `json:"users"`
}
type UserConfig struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Level      int    `json:"level"`
}
type StreamSettings struct {
	Network     string        `json:"network"`
	Security    string        `json:"security"`
	TLSSettings TLSSettings   `json:"tlsSettings"`
	WSSettings  WSSettings    `json:"wsSettings"`
	Sockopt     SockoptConfig `json:"sockopt"`
}
type TLSSettings struct {
	ServerName    string `json:"serverName"`
	AllowInsecure bool   `json:"allowInsecure"`
	Fingerprint   string `json:"fingerprint"`
}
type WSSettings struct {
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	ReadBuf  int               `json:"readBufSize,omitempty"`
	WriteBuf int               `json:"writeBufSize,omitempty"`
}
type SockoptConfig struct {
	TCPFastOpen    bool `json:"tcpFastOpen"`
	KeepAlive      int  `json:"keepAlive"`
	TCPKeepAlive   int  `json:"tcpKeepAlive"`
	BufferSize     int  `json:"bufferSize"`
	TCPWindowClamp int  `json:"tcpWindowClamp,omitempty"`
}
type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}
type PolicyConfig struct {
	Levels map[int]LevelPolicy `json:"levels"`
	System SystemPolicy        `json:"system"`
}
type LevelPolicy struct {
	Handshake    int `json:"handshake"`
	ConnIdle     int `json:"connIdle"`
	UplinkOnly   int `json:"uplinkOnly"`
	DownlinkOnly int `json:"downlinkOnly"`
	BufferSize   int `json:"bufferSize"`
}
type SystemPolicy struct {
	StatsInboundUDP  bool `json:"statsInboundUDP"`
	StatsOutboundUDP bool `json:"statsOutboundUDP"`
}

// ── Windows API ───────────────────────────────────────────────────────────────

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	wininet            = windows.NewLazySystemDLL("wininet.dll")
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	setConsoleTitleW   = kernel32.NewProc("SetConsoleTitleW")
	internetSetOptionW = wininet.NewProc("InternetSetOptionW")
	getAdaptersAddresses = iphlpapi.NewProc("GetAdaptersAddresses")
)

func setConsoleTitle(title string) {
	ptr, _ := syscall.UTF16PtrFromString(title)
	setConsoleTitleW.Call(uintptr(unsafe.Pointer(ptr)))
}

func refreshProxySettings() {
	internetSetOptionW.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	internetSetOptionW.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
}

// ── MIB_IFTABLE (v1) ─────────────────────────────────────────────────────────

// MIB_IFROW is the v1 interface row — fixed size, no alignment ambiguity
type MIB_IFROW struct {
	Name            [256]uint16
	Index           uint32
	Type            uint32
	Mtu             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [8]byte
	AdminStatus     uint32
	OperStatus      uint32
	LastChange      uint32
	InOctets        uint32
	InUcastPkts     uint32
	InNUcastPkts    uint32
	InDiscards      uint32
	InErrors        uint32
	InUnknownProtos uint32
	OutOctets       uint32
	OutUcastPkts    uint32
	OutNUcastPkts   uint32
	OutDiscards     uint32
	OutErrors       uint32
	OutQLen         uint32
	DescrLen        uint32
	Descr           [256]byte
}

var getIfTable = iphlpapi.NewProc("GetIfTable")

func getNetworkStatsV1() (recv uint64, sent uint64, err error) {
	var size uint32
	getIfTable.Call(0, uintptr(unsafe.Pointer(&size)), 1)

	if size == 0 {
		return 0, 0, fmt.Errorf("GetIfTable: zero size")
	}

	buf := make([]byte, size)
	ret, _, _ := getIfTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
	)
	if ret != 0 {
		return 0, 0, fmt.Errorf("GetIfTable failed: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(MIB_IFROW{})

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if int(offset)+int(rowSize) > len(buf) {
			break
		}
		row := (*MIB_IFROW)(unsafe.Pointer(&buf[offset]))

		if row.Type == IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		// OperStatus 5 = CONNECTED, 6 = OPERATIONAL
		if row.OperStatus < 5 {
			continue
		}

		recv += uint64(row.InOctets)
		sent += uint64(row.OutOctets)
	}
	return recv, sent, nil
}

// ── Traffic tracking ──────────────────────────────────────────────────────────

var totalTunnelBytes uint64

type ConnTracker struct {
	sync.Mutex
	connections map[string]*Connection
}

type Connection struct {
	Dest      string
	StartTime time.Time
	Bytes     uint64
	Active    bool
	mu        sync.Mutex
}

var tracker = &ConnTracker{connections: make(map[string]*Connection)}
var stopCh = make(chan struct{})

func (t *ConnTracker) addConnection(dest string) {
	t.Lock()
	defer t.Unlock()
	if c, ok := t.connections[dest]; ok {
		c.mu.Lock()
		c.Active = true
		c.mu.Unlock()
		return
	}
	t.connections[dest] = &Connection{
		Dest:      dest,
		StartTime: time.Now(),
		Active:    true,
	}
}

func (t *ConnTracker) markInactive(dest string) {
	t.Lock()
	defer t.Unlock()
	if c, ok := t.connections[dest]; ok {
		c.mu.Lock()
		c.Active = false
		c.mu.Unlock()
	}
}

func (t *ConnTracker) getMB(dest string) float64 {
	t.Lock()
	defer t.Unlock()
	if c, ok := t.connections[dest]; ok {
		c.mu.Lock()
		defer c.mu.Unlock()
		return float64(c.Bytes) / (1024 * 1024)
	}
	return 0
}

// ── Speed monitor (title bar) ─────────────────────────────────────────────────

func speedMonitor() {
	baseRecv, baseSent, err := getNetworkStatsV1()
	if err != nil {
		fmt.Printf("\033[31m[WARN] getNetworkStats seed failed: %v\033[0m\n", err)
	}
	lastRecv, lastSent := baseRecv, baseSent
	var cumRecv, cumSent uint64

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			recv, sent, err := getNetworkStatsV1()
			if err != nil {
				setConsoleTitle(fmt.Sprintf("%s | stats error", tunnelDisplayName))
				continue
			}

			var dRecv, dSent uint64
			if recv >= lastRecv {
				dRecv = recv - lastRecv
			}
			if sent >= lastSent {
				dSent = sent - lastSent
			}
			lastRecv, lastSent = recv, sent

			const maxPlausible = 1024 * 1024 * 1024
			if dRecv > maxPlausible || dSent > maxPlausible {
				continue
			}

			cumRecv += dRecv
			cumSent += dSent
			atomic.StoreUint64(&totalTunnelBytes, cumRecv+cumSent)

			downMB := float64(dRecv) / 1024 / 1024
			upMB := float64(dSent) / 1024 / 1024
			totalMB := float64(cumRecv+cumSent) / 1024 / 1024

			title := fmt.Sprintf(
				"%s  |  ↓ %.2f MB/s  |  ↑ %.2f MB/s  |  Session: %.2f MB",
				tunnelDisplayName, downMB, upMB, totalMB,
			)
			setConsoleTitle(title)
		}
	}
}

// ── Traffic attribution (per-connection byte share) ───────────────────────────

func startTrafficAttribution() {
	baseRecv, baseSent, _ := getNetworkStatsV1()
	lastTotal := baseRecv + baseSent

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			recv, sent, err := getNetworkStatsV1()
			if err != nil {
				continue
			}
			nowTotal := recv + sent

			var delta uint64
			if nowTotal >= lastTotal {
				delta = nowTotal - lastTotal
			}
			lastTotal = nowTotal

			if delta == 0 || delta > 500*1024*1024 {
				continue
			}

			tracker.Lock()
			var active []*Connection
			for _, c := range tracker.connections {
				c.mu.Lock()
				if c.Active {
					active = append(active, c)
				}
				c.mu.Unlock()
			}
			tracker.Unlock()

			if len(active) == 0 {
				continue
			}
			perConn := delta / uint64(len(active))
			for _, c := range active {
				c.mu.Lock()
				c.Bytes += perConn
				c.mu.Unlock()
			}
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func getIP(proxyURL *url.URL) string {
	client := &http.Client{Timeout: 8 * time.Second}
	if proxyURL != nil {
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if ip, ok := result["ip"].(string); ok {
		return ip
	}
	return "Unknown"
}

func setWindowsProxy(enable bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if enable {
		key.SetDWordValue("ProxyEnable", 1)
		key.SetStringValue("ProxyServer", fmt.Sprintf("127.0.0.1:%d", toolConfig.LocalPort))
		key.SetStringValue("ProxyOverride", "<local>")
	} else {
		key.SetDWordValue("ProxyEnable", 0)
	}
	refreshProxySettings()
	return nil
}

func generateXrayConfig() *XrayConfig {
	return &XrayConfig{
		Log: LogConfig{Loglevel: "warning"},
		Policy: PolicyConfig{
			Levels: map[int]LevelPolicy{
				0: {Handshake: 4, ConnIdle: 300, UplinkOnly: 2, DownlinkOnly: 2, BufferSize: 20480},
			},
			System: SystemPolicy{StatsInboundUDP: true, StatsOutboundUDP: true},
		},
		Inbounds: []InboundConfig{{
			Port:     toolConfig.LocalPort,
			Listen:   "127.0.0.1",
			Protocol: "socks",
			Sniffing: SniffingConfig{Enabled: true, DestOverride: []string{"http", "tls"}},
			Settings: InboundSettings{UDP: true, Auth: "noauth"},
		}},
		Outbounds: []OutboundConfig{{
			Protocol: "vless",
			Settings: OutboundSettings{VNext: []VNextConfig{{
				Address: toolConfig.ServerAddress,
				Port:    toolConfig.ServerPort,
				Users:   []UserConfig{{ID: toolConfig.UserID, Encryption: "none", Level: 0}},
			}}},
			StreamSettings: StreamSettings{
				Network:  "ws",
				Security: "tls",
				TLSSettings: TLSSettings{
					ServerName:    toolConfig.SNIHost,
					AllowInsecure: true,
					Fingerprint:   "chrome",
				},
				WSSettings: WSSettings{
					Path:     toolConfig.Path,
					Headers:  map[string]string{"Host": toolConfig.ServerAddress},
					ReadBuf:  65536,
					WriteBuf: 65536,
				},
				Sockopt: SockoptConfig{
					TCPFastOpen:    true,
					KeepAlive:      30,
					TCPKeepAlive:   30,
					BufferSize:     32768,
					TCPWindowClamp: 65535,
				},
			},
			Mux: MuxConfig{Enabled: true, Concurrency: 16},
		}},
	}
}

// ── Log parsing ───────────────────────────────────────────────────────────────

var acceptRegex = regexp.MustCompile(`accepted\s+(?:tcp:|udp:)?([^\s\[]+)`)

func parseDest(line string) string {
	m := acceptRegex.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	dest := strings.TrimSpace(m[1])
	if !strings.Contains(dest, ":") {
		dest += ":443"
	}
	return dest
}

// ── Load configuration from JSON file ─────────────────────────────────────────

func loadConfig() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		// Create default config file
		defaultCfg := ToolConfig{
			ExePath:       `E:\softwares\v2ray\xray.exe`,
			LocalPort:     10808,
			SNIHost:       "m.facebook.com",
			ServerAddress: "seaseus.pp.ua",
			ServerPort:    443,
			UserID:        "ab73296c-6f34-4684-94d6-770053cd4367",
			Path:          "/seaseus",
			TunnelName:    "",
		}
		defData, _ := json.MarshalIndent(defaultCfg, "", "  ")
		if err := os.WriteFile("config.json", defData, 0644); err != nil {
			return fmt.Errorf("could not create default config.json: %w", err)
		}
		return fmt.Errorf("config.json not found. A default file has been created. Please edit it and run again.")
	}
	if err := json.Unmarshal(data, &toolConfig); err != nil {
		return fmt.Errorf("invalid config.json: %w", err)
	}
	
	// Set tunnel display name
	if toolConfig.TunnelName != "" {
		tunnelDisplayName = toolConfig.TunnelName
	} else if toolConfig.SNIHost != "" {
		tunnelDisplayName = strings.Split(toolConfig.SNIHost, ".")[0] + " Tunnel"
	} else {
		tunnelDisplayName = "Secure Tunnel"
	}
	
	// Basic validation
	if toolConfig.ExePath == "" || toolConfig.LocalPort == 0 || toolConfig.UserID == "" {
		return fmt.Errorf("missing required fields in config.json")
	}
	return nil
}

// ── Banner ────────────────────────────────────────────────────────────────────

func printBanner() {
	fmt.Println("\033[36m╔══════════════════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[36m║           Secure Tunnel Manager - by Ishan Oshada           ║\033[0m")
	fmt.Println("\033[36m║              github.com/ishanoshada                          ║\033[0m")
	fmt.Println("\033[36m╚══════════════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	if runtime.GOOS == "windows" {
		exec.Command("chcp", "65001").Run()
	}

	printBanner()

	// Load configuration
	if err := loadConfig(); err != nil {
		fmt.Printf("\033[31m[ERROR] %v\033[0m\n", err)
		os.Exit(1)
	}

	fmt.Printf("\033[33m[*] Tunnel: %s\033[0m\n", tunnelDisplayName)
	fmt.Printf("\033[33m[*] Server: %s:%d\033[0m\n", toolConfig.ServerAddress, toolConfig.ServerPort)
	fmt.Printf("\033[33m[*] SNI: %s\033[0m\n", toolConfig.SNIHost)

	// Quick self-test of network stats
	r, s, err := getNetworkStatsV1()
	if err != nil {
		fmt.Printf("\033[31m[ERROR] Network stats unavailable: %v\033[0m\n", err)
	} else {
		fmt.Printf("\033[90m[DEBUG] Stats OK — recv: %d KB, sent: %d KB\033[0m\n", r/1024, s/1024)
	}

	fmt.Println("\033[33m[*] Checking current IP...\033[0m")
	beforeIP := getIP(nil)
	fmt.Printf("\033[36m[BEFORE] IP: %s\033[0m\n", beforeIP)

	if err := setWindowsProxy(true); err != nil {
		fmt.Printf("\033[31mProxy error: %v\033[0m\n", err)
		os.Exit(1)
	}
	fmt.Println("\033[35m[!] Starting tunnel...\033[0m")

	cfg := generateXrayConfig()
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile("xray_runtime.json", cfgData, 0644); err != nil {
		fmt.Printf("Failed to write xray config: %v\n", err)
		os.Exit(1)
	}

	go speedMonitor()
	go startTrafficAttribution()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, toolConfig.ExePath, "-c", "xray_runtime.json")
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("\033[31mFailed to start xray: %v\033[0m\n", err)
		os.Exit(1)
	}

	fmt.Println("\033[33m[*] Waiting for tunnel to come up...\033[0m")
	time.Sleep(3 * time.Second)

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", toolConfig.LocalPort))
	afterIP := getIP(proxyURL)
	fmt.Printf("\033[36m[AFTER]  IP: %s\033[0m\n", afterIP)
	fmt.Println("------------------------------------------------------------")

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "accepted") {
				continue
			}
			dest := parseDest(line)
			if dest == "" {
				fmt.Printf("\033[32m[CONN]\033[0m %s\n", line)
				continue
			}

			tracker.addConnection(dest)
			go func(d string) {
				time.Sleep(30 * time.Second)
				tracker.markInactive(d)
			}(dest)

			connMB := tracker.getMB(dest)
			sessMB := float64(atomic.LoadUint64(&totalTunnelBytes)) / 1024 / 1024
			fmt.Printf(
				"\033[32m[CONN]\033[0m %-45s \033[36m%.2f mb\033[0m  \033[33m[↕ %.2f mb]\033[0m\n",
				dest, connMB, sessMB,
			)
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			// suppress stderr or handle if needed
			_ = scanner.Text()
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n\033[31m[!] Shutting down...\033[0m")
	close(stopCh)
	cancel()
	cmd.Wait()
	setWindowsProxy(false)
	os.Remove("xray_runtime.json")
	fmt.Println("\033[32m[✓] Proxy disabled.\033[0m")
}

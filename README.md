# 🔒 Secure Tunnel for Windows - Whole Internet Proxy

[![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat&logo=windows)](https://microsoft.com/windows)
[![GitHub Actions](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?style=flat&logo=github-actions)](https://github.com/features/actions)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<center>

![1](/img/image.png)


**Unlike HTTP Injector (which only works for specific apps/packages), this tunnel routes YOUR ENTIRE WINDOWS INTERNET TRAFFIC through a secure proxy - every browser, every app, every program!**

**Created by Ishan Oshada** | [GitHub](https://github.com/ishanoshada)


</center>

## 🌟 What Makes This Different?

### ❌ HTTP Injector Limitations (Android/PC)
- Only works for specific app packages
- Requires manual configuration per app
- Limited to HTTP/HTTPS traffic
- No system-wide integration

### ✅ This Tool Advantages
- **WHOLE INTERNET** - Every Windows application uses the proxy
- **SYSTEM-WIDE** - No app-specific configuration needed
- **ALL TRAFFIC** - HTTP, HTTPS, TCP, UDP, games, browsers, downloads
- **AUTO CONFIG** - Windows system proxy automatically enabled/disabled
- **REAL-TIME STATS** - Live bandwidth monitoring for all connections

**Think of it as a VPN, but faster and more efficient!**

---

## 📋 Features

- 🚀 **Full Windows System Proxy** - Routes ALL internet traffic
- 📊 **Real-time Traffic Monitor** - Live speed display in console title bar
- 🔗 **Per-Connection Tracking** - See bandwidth usage per destination
- 🎯 **Smart SNI Detection** - Automatically captures domain names
- 💾 **Low Resource Usage** - Minimal CPU and memory footprint
- 🔄 **Graceful Shutdown** - Automatically restores proxy settings
- 📝 **Configurable** - Easy JSON configuration file
- 🌐 **SOCKS5 Proxy** - Compatible with all Windows apps
- 🤖 **GitHub Actions CI/CD** - Automatic builds on every push

---

## 📥 Prerequisites

### Operating System
- **Windows 10/11** (64-bit required)
- Windows 8/8.1 (64-bit, may work)

### Required Software

#### 1. Download Xray Core (The Proxy Engine)

Xray is the core engine that creates the encrypted tunnel. Download the latest Windows version:

**Method 1: Direct Download (Recommended)**
```bash
# Visit official releases
https://github.com/XTLS/Xray-core/releases/latest

# Download for Windows 64-bit:
Xray-windows-64.zip

# For 32-bit Windows:
Xray-windows-32.zip
```

**Method 2: Using PowerShell (Automated)**
```powershell
# Create directory
New-Item -ItemType Directory -Force -Path "E:\softwares\v2ray"

# Download latest Xray for Windows 64-bit
Invoke-WebRequest -Uri "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip" -OutFile "E:\softwares\v2ray\xray.zip"

# Extract
Expand-Archive -Path "E:\softwares\v2ray\xray.zip" -DestinationPath "E:\softwares\v2ray\" -Force

# Remove zip
Remove-Item "E:\softwares\v2ray\xray.zip"

# Test installation
E:\softwares\v2ray\xray.exe -version
```

**Method 3: Manual Download**
1. Go to: https://github.com/XTLS/Xray-core/releases
2. Download `Xray-windows-64.zip`
3. Extract to `E:\softwares\v2ray\` or `C:\xray\`
4. Verify `xray.exe` exists in that folder

#### 2. Git (Optional - for development)
```powershell
# Download from
https://git-scm.com/download/win
```

#### 3. Go Compiler (Only if building from source)
```powershell
# Download Go from
https://golang.org/dl/

# Download Windows .msi installer (e.g., go1.21.0.windows-amd64.msi)
# Run installer and follow instructions
```

---

## 🚀 Installation & Setup

To make the download as easy as possible for users, you can use a direct link to the "raw" file in your repository. This allows them to click and save the file immediately.

Here is the updated **Option 1** section to add to your `README.md`:

---

### Option 1: Download Pre-built Binary (Easiest)

**From GitHub Main Branch:**
1. **[Download secure-tunnel.exe](https://github.com/Ishanoshada/Secure-Tunnel-Windows/raw/main/bin/windows_x64/secure-tunnel.exe)** (Click to download latest build)
2. Place the file in any folder (e.g., `C:\tunnel\`)
3. Ensure you also have your `config.json` in the same folder.
4. **Note:** Some browsers may flag the `.exe` as "unrecognized"—click "Keep" or "Run anyway" as this is a custom-built tool.


### Option 2: Build from Source (For Developers)

```powershell
# Step 1: Clone the repository
git clone https://github.com/ishanoshada/Secure-Tunnel-Windows.git
cd Secure-Tunnel-Windows

# Step 2: Initialize Go module
go mod init secure-tunnel

# Step 3: Download dependencies
go mod tidy

# Step 4: Build the executable
# For console version (shows window - good for debugging)
go build -o secure-tunnel.exe main.go


# Step 5: (Optional) Move to bin folder
mkdir bin\windows_x64
move secure-tunnel.exe bin\windows_x64\
```

**Build Commands Explained:**
- `go mod init secure-tunnel` - Creates go.mod file for dependency management
- `go mod tidy` - Downloads required dependencies (golang.org/x/sys/windows)
- `go build -o secure-tunnel.exe main.go` - Compiles to executable

---

## ⚙️ Configuration

### Step 1: Create config.json

Create `config.json` in the same folder as `secure-tunnel.exe`:

```json
{
  "exePath": "E:\\softwares\\v2ray\\xray.exe",
  "localPort": 10808,
  "sniHost": "m.facebook.com",
  "serverAddress": "your-server.com",
  "serverPort": 443,
  "userID": "your-uuid-here",
  "path": "/your-path",
  "tunnelName": "My Secure Tunnel"
}
```
### 🌐 Popular  SNI Host List

You can use these SNI hosts in your `config.json` depending on your active internet package. This allows the tunnel to bypass billing or use dedicated data packages.

| Package / App | SNI Host (Use in `sniHost` field) |
| :--- | :--- |
| **Facebook & WhatsApp** | `m.facebook.com` |
| **Zoom (Learn from Home)** | `zoom.us` or `vln02.zoom.us` |
| **Microsoft Teams** | `teams.microsoft.com` |
| **Google Services** | `[www.google.com](https://www.google.com)` |
| **Dialog Unlimited (Social)** | `free.facebook.com` |
| **Mobitel (Social)** | `m.facebook.com` |
| **SLT Learn from Home** | `zoom.us` |
| **Generic/Cloudflare** | `cdn.cloudflare.com` |

---


### Step 2: Configuration Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `exePath` | Full path to `xray.exe` | `E:\\softwares\\v2ray\\xray.exe` |
| `localPort` | Local SOCKS5 proxy port | `10808` |
| `sniHost` | SNI host for TLS fingerprint (can be any domain) | `m.facebook.com`, `www.google.com`, `cdn.cloudflare.com` |
| `serverAddress` | Your VLESS server address | `seaseus.pp.ua` |
| `serverPort` | VLESS server port | `443` |
| `userID` | VLESS user UUID | `ab73296c-6f34-4684-..........` |
| `path` | WebSocket path | `/seaseus` |
| `tunnelName` | Custom tunnel name (optional) | `My Tunnel` |

### Step 3: Get Your Server Configuration

You need a VLESS+WebSocket+TLS server. Get from:
- **Your own VPS** with Xray installed (DigitalOcean, Vultr, AWS - $3-10/month)
- **Service providers** offering VLESS configs
- **Generate using Xray** on your server

**Server Requirements:**
- Protocol: VLESS
- Transport: WebSocket (WS)
- Security: TLS
- Encryption: none
- Network: TCP (port 443 usually)

---

## 🎮 Usage

### Basic Usage (Everything uses the tunnel)

```powershell
# Navigate to tool directory
cd C:\tunnel\

# Run the tunnel
secure-tunnel.exe

#secure-tunnel.exe --config path
# The console will show:
# - Your real IP before connection
# - Your tunnel IP after connection
# - Live speed in the title bar
# - Every connection with bandwidth usage
```

### What Happens When You Run:

1. **Tool starts** and reads config.json
2. **Enables Windows system proxy** (settings applied)
3. **Starts Xray core** (establishes encrypted tunnel)
4. **ALL your internet traffic** now goes through the tunnel:
   - Microsoft Edge / Chrome / Firefox
   - WhatsApp Desktop / Telegram / Discord
   - Steam / Epic Games / Minecraft
   - Windows Update / Microsoft Store
   - Any app that uses the internet!

### Example Output

```
╔══════════════════════════════════════════════════════════════╗
║           Secure Tunnel Manager - by Ishan Oshada           ║
║              github.com/ishanoshada                          ║
╚══════════════════════════════════════════════════════════════╝

[*] Tunnel: My Secure Tunnel
[*] Server: your-server.com:443
[*] SNI: m.facebook.com
[DEBUG] Stats OK — recv: 15690109 KB, sent: 524288 KB
[*] Checking current IP...
[BEFORE] IP: 192.168.1.100 (Your real IP)
[!] Starting tunnel...
[*] Waiting for tunnel to come up...
[AFTER]  IP: 203.0.113.50 (Tunnel IP - different country/region)
------------------------------------------------------------
[CONN] google.com:443                                     0.15 mb  [↕ 1.23 mb]
[CONN] github.com:443                                     0.42 mb  [↕ 1.65 mb]
[CONN] cdn.discordapp.com:443                             0.08 mb  [↕ 1.73 mb]
[CONN] api.telegram.org:443                               0.23 mb  [↕ 1.96 mb]
[CONN] windows.update.com:80                              0.01 mb  [↕ 1.97 mb]
```

### Console Title Bar (Real-time Stats)

The window title shows your current speed and total usage:

```
My Secure Tunnel | ↓ 1.23 MB/s | ↑ 0.45 MB/s | Session: 125.67 MB
```

### Verifying Everything is Tunneled

**Check your IP:**
```powershell
# Before tunnel - your real IP
curl ifconfig.me

# After tunnel starts - your tunnel IP (should be different)
curl --proxy socks5h://127.0.0.1:10808 ifconfig.me
```

**Test in Browser:**
1. Open Chrome/Edge
2. Visit `https://whatismyip.com`
3. Should show your tunnel IP, not your real IP

**Test in Apps:**
- Open WhatsApp Desktop - works through tunnel
- Open Telegram - works through tunnel
- Download a file - goes through tunnel

### Stopping the Tunnel

Press `Ctrl+C` in the console window - system proxy automatically disabled, internet reverts to normal.

**IMPORTANT:** Always stop with Ctrl+C, not by closing the window!

---

## 🆚 Comparison: This Tool vs HTTP Injector

| Feature | HTTP Injector (Android/PC) | This Windows Tool |
|---------|---------------------------|-------------------|
| **Scope** | Specific app packages only | **ENTIRE WINDOWS SYSTEM** |
| **Configuration** | Per-app setup required | **AUTO - Set once** |
| **Browser Support** | Manual proxy setup | **AUTOMATIC** |
| **Game Traffic** | Usually not supported | **YES - Full support** |
| **Windows Updates** | No | **YES** |
| **UDP Traffic** | Limited | **YES** |
| **Background Apps** | No | **YES** |
| **Real-time Stats** | Basic | **Advanced with per-connection** |
| **Resource Usage** | High (Java/Android emulation) |
---

## ❓ FAQ

**Q: Is this a VPN?**
A: No, it's a SOCKS5 proxy tunnel. It works similarly but only for applications that support SOCKS5 proxies.

**Q: Can I use this with any browser?**
A: Yes! All major browsers respect Windows system proxy settings.

**Q: Does it work with games?**
A: Most games work, but some use UDP which requires additional configuration.

**Q: How much does it cost?**
A: The tool is free and open-source. You need your own VLESS server (VPS costs $3-10/month).

**Q: Can I use multiple tunnels?**
A: Run multiple instances with different local ports and config files.

**Q: Why does it show "Stats OK" but no traffic?**
A: The stats show total system traffic. If no tunnel traffic, check your server configuration.

**Q: How to auto-start with Windows?**
A: Create a shortcut in `shell:startup` pointing to your executable.

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ishanoshada/secure-tunnel-windows/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ishanoshada/secure-tunnel-windows/discussions)
- **Email**: [ic31908@gmail.com]

---

## 📜 License

MIT License - Free for personal and commercial use.

---

## 🙏 Acknowledgments

- [Xray-core](https://github.com/XTLS/Xray-core) - The core proxy engine
- [Project V](https://www.v2fly.org/) - VLESS protocol design
- All contributors and users

---

## ⭐ Star History

If you find this tool useful, please star the repository on GitHub!

---

<center>

**Made with ❤️ by Ishan Oshada**  
**Windows • Secure • Fast • Free**

</center>
<div align="center">

# 📡 Wi-Fi Deauther - Educational Tool

**A comprehensive educational tool for Wi-Fi network analysis, scanning, and security testing**

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Educational%20Use%20Only-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/devil136-star)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-green.svg)](https://scapy.net/)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [Author](#-author)

---

</div>

## ⚠️ **IMPORTANT WARNING**

<div align="center">

### 🚨 **FOR EDUCATIONAL PURPOSES ONLY** 🚨

**Unauthorized access to computer networks is ILLEGAL in many jurisdictions.**

Use only on networks you own or have explicit written permission to test.

**The authors are NOT responsible for any misuse of this tool.**

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Legal and Ethical Considerations](#-legal-and-ethical-considerations)
- [Troubleshooting](#-troubleshooting)
- [Technical Details](#-technical-details)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Network Scanning** | Discover available Wi-Fi networks with detailed information (SSID, BSSID, Signal Strength, Channel, Encryption) |
| 📡 **Deauthentication** | Send deauthentication packets for educational testing (use only on your own networks!) |
| 📊 **Network Monitoring** | Monitor and analyze traffic on specific networks in real-time |
| 🖥️ **CLI Interface** | Simple, menu-driven command-line interface for advanced users |
| 🎨 **GUI Interface** | User-friendly graphical interface with tabs and visual feedback |
| 🔒 **Security Testing** | Educational tool for understanding Wi-Fi security mechanisms |

---

## 📦 Prerequisites

Before installing, ensure you have:

- ✅ **Python 3.7+** installed
- ✅ **Administrator/Root privileges** (required for packet injection)
- ✅ **Wireless network adapter** that supports monitor mode
- ✅ **Windows**: [Npcap](https://nmap.org/npcap/) (recommended) or WinPcap installed
- ✅ **Linux**: Wireless tools installed

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/devil136-star/WIFI.git
cd WIFI
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Platform-Specific Setup

#### 🪟 Windows

1. Install [Npcap](https://nmap.org/npcap/) (recommended over WinPcap)
2. Run PowerShell/Command Prompt as **Administrator**
3. The GUI uses `tkinter`, which is usually pre-installed with Python

#### 🐧 Linux

```bash
# Install wireless tools
sudo apt-get update
sudo apt-get install python3-pip wireless-tools python3-tk

# Or for RHEL/CentOS
sudo yum install python3-pip wireless-tools python3-tkinter
```

---

## 💻 Usage

### 🎨 GUI Version (Recommended for Beginners)

**Windows:**
```powershell
# Run PowerShell as Administrator
python wifi_deauther_gui.py

# Or simply double-click
run_gui.bat
```

**Linux:**
```bash
# Run with sudo for packet injection
sudo python3 wifi_deauther_gui.py
```

#### GUI Features:
- 📡 **Network Scanner Tab**: Easy network scanning with visual results table
- ⚡ **Deauthentication Tab**: Simple controls for deauth attacks
- 📊 **Network Monitor Tab**: Real-time monitoring with detailed logs
- ℹ️ **Information Tab**: Built-in help and usage instructions

### 🖥️ CLI Version

**Windows:**
```powershell
# Run PowerShell as Administrator
python wifi_deauther.py

# Or double-click
run_cli.bat
```

**Linux:**
```bash
# Run with sudo for packet injection
sudo python3 wifi_deauther.py
```

#### CLI Menu Options:

1. **Scan for Wi-Fi Networks** - Discover available networks
2. **Display Scanned Networks** - Show previously scanned networks
3. **Deauthenticate Network (Broadcast)** - Disconnect all devices from a network
4. **Deauthenticate Specific Client** - Target a specific device
5. **Monitor Network Traffic** - Monitor packets on a specific network
6. **Show Available Interfaces** - List available network interfaces
7. **Exit** - Close the application

### 📝 Example Workflow

```bash
1. Start the tool with Administrator/Root privileges
2. Select option 1 to scan for networks
3. Wait for the scan to complete (default: 10 seconds)
4. Select option 2 to view discovered networks
5. Choose a network for testing (ONLY networks you own!)
6. Use options 3-5 for various operations
```

---

## 🔧 How It Works

### Network Scanning
- Uses **802.11 beacon frames** to discover networks passively
- Captures: SSID, BSSID, signal strength, channel, and encryption type
- **Passive scanning** (does not transmit, only receives)

### Deauthentication
- Sends **802.11 deauthentication frames**
- Can target all clients (broadcast) or specific devices
- Uses reason code 7 (Class 3 frame received from nonassociated station)

### Network Monitoring
- Captures and analyzes packets on a specific network
- Displays packet types, subtypes, and source/destination addresses
- Provides comprehensive traffic statistics

---

## ⚖️ Legal and Ethical Considerations

### ✅ Legal Uses

- ✅ Testing your own networks
- ✅ Authorized penetration testing
- ✅ Educational learning and research
- ✅ Security auditing with written permission

### ❌ Illegal Uses

- ❌ Attacking networks without permission
- ❌ Disrupting public or private networks
- ❌ Unauthorized access attempts
- ❌ Any malicious activity

> **⚠️ Remember**: Even if a network is unsecured, accessing it without permission may be illegal.

---

## 🔍 Troubleshooting

### "No networks found"
- ✅ Ensure your wireless adapter is enabled
- ✅ Check that you have the correct interface selected
- ✅ Verify monitor mode is supported (Linux)
- ✅ Try running with administrator/root privileges
- ✅ Increase scan duration (try 30+ seconds)

### "Permission denied" or "Operation not permitted"
- ✅ Run with administrator/root privileges
- ✅ On Linux, ensure your user is in the appropriate groups
- ✅ Check that your wireless adapter supports monitor mode

### "Interface not found"
- ✅ List available interfaces using option 6 (CLI) or interface dropdown (GUI)
- ✅ Ensure your wireless adapter is connected
- ✅ On Windows, check device manager for adapter name

### Windows-Specific Issues
- ✅ Ensure **Npcap** (not WinPcap) is installed
- ✅ Run as Administrator
- ✅ Some wireless adapters may not support packet injection on Windows

---

## 📚 Technical Details

| Aspect | Details |
|--------|---------|
| **Protocol** | IEEE 802.11 (Wi-Fi) |
| **Library** | Scapy 2.5+ |
| **Supported Standards** | 802.11a/b/g/n/ac |
| **Platforms** | Windows, Linux, macOS (with limitations) |
| **GUI Framework** | Tkinter (Python standard library) |

---

## 📖 Educational Resources

- [IEEE 802.11 Standard](https://standards.ieee.org/standard/802_11.html)
- [Wi-Fi Security Best Practices](https://www.wi-fi.org/discover-wi-fi/security)
- [Network Security Fundamentals](https://www.cisco.com/c/en/us/products/security/what-is-network-security.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)

---

## 🤝 Contributing

This is an educational project. Contributions that improve:

- ✨ Code quality and documentation
- 📚 Educational value
- ⚠️ Safety warnings and legal disclaimers
- 🔧 Cross-platform compatibility

...are welcome!

### How to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 👨‍💻 Author

<div align="center">

### **Himanshu Kumar**

**Cybersecurity Enthusiast | Developer | Ethical Hacker**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/devil136-star)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/himanshu-kumar-777a50292/)

**Connect with me:**
- 🔗 **GitHub**: [@devil136-star](https://github.com/devil136-star)
- 💼 **LinkedIn**: [Himanshu Kumar](https://www.linkedin.com/in/himanshu-kumar-777a50292/)

---

</div>

---

## 📄 License

**Educational Use Only**

This software is provided for educational purposes. Users are responsible for ensuring their use complies with all applicable laws and regulations.

---

## ⚠️ Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE AUTHORS SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE. USE AT YOUR OWN RISK AND IN COMPLIANCE WITH ALL APPLICABLE LAWS.

---

<div align="center">

### 🌟 **Star this repo if you find it helpful!** ⭐

---

**Stay Legal. Stay Ethical. Stay Safe.** 🛡️

Made with ❤️ by [Himanshu Kumar](https://github.com/devil136-star)

</div>

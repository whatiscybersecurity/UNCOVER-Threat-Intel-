```
01110101 01101110 01100011 01101111 01110110 01100101 01110010
   u        n        c        o        v        e        r
```

# 🛡️ Uncover

**IP Threat Intelligence Tool**

A modern, feature-rich GUI application for IP address reconnaissance and threat intelligence gathering. Uncover combines multiple security APIs and scanning tools into one sleek interface.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

---

## ✨ Features

- **🔍 AbuseIPDB Integration** - Check IP reputation, abuse confidence scores, and report history
- **🔎 Shodan Lookup** - Discover open ports, services, vulnerabilities, and host information
- **🔧 Nmap Scanning** - Run service version detection scans directly from the GUI
- **🗺️ Interactive Map** - Visualize IP geolocation with an interactive map view
- **🌙 Dark/Light Mode** - Easy on the eyes with theme toggling
- **📊 Clean Results Display** - Organized, color-coded output for quick analysis

---

## 📸 Screenshots
<video controls src="Observer GIF.mp4" title="Title"></video>
---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- Nmap (optional, for port scanning)

### Setup

1. **Clone the repository**
```bash
   git clone https://github.com/YOUR_GITHUB_USERNAME/uncover.git
   cd uncover
```

2. **Install dependencies**
```bash
   pip install requests tkintermapview
```

3. **Install Nmap** (optional)
   - Windows: Download from [nmap.org](https://nmap.org/download.html)
   - Linux: `sudo apt install nmap`
   - macOS: `brew install nmap`

4. **Run the application**
```bash
   python uncover.py
```

---

## 🔑 API Keys

You'll need API keys for full functionality:

| Service | Required | Get Key |
|---------|----------|---------|
| AbuseIPDB | Yes | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| Shodan | Optional | [shodan.io](https://account.shodan.io/) |

---

## 📖 Usage

1. Enter the target IP address
2. Add your API keys
3. Click **Check IP** for AbuseIPDB threat intelligence
4. Click **Shodan Lookup** for open ports and services
5. Click **Nmap Scan** for active port scanning

---

## 🛠️ Built With

- **Python** - Core language
- **Tkinter** - GUI framework
- **Requests** - API calls
- **TkinterMapView** - Interactive maps
- **Nmap** - Port scanning

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and research purposes only**. Only scan IP addresses you have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Feel free to submit a Pull Request.


```
01110101 01101110 01100011 01101111 01110110 01100101 01110010
```
```


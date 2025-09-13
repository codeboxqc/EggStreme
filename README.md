[README (1).md](https://github.com/user-attachments/files/22311047/README.1.md)
# ?? EggStreme IOC Scanner

EggStreme is a Windows console tool that scans processes and network connections for suspicious activity using known IOCs (Indicators of Compromise).

 ips.txt 
 domains.txt 
 urls.txt 
 hashes.txt 
 regex.txt 

 this file ARE in the realase to get exe to run it load content

---

## ?? Features
- **Configurable feeds** via `config.json` (supports CSV, TXT, JSON).
- **Local IOC loading** from `ips.txt`, `domains.txt`, `urls.txt`, `hashes.txt`, `regex.txt`.
- **Feed fetching & caching** using WinINet with automatic staleness detection (1 hour).
- **IOC matching** against:
  - IP addresses  
  - Domain names  
  - URLs  
  - File hashes (MD5/SHA1/SHA256 length heuristics)  
  - Regex patterns
- **Process scanning**: extracts process command lines (via `NtQueryInformationProcess` + PEB parsing).
- **Network scanning**: enumerates TCP connections and matches against IOC IPs.
- **Webhook alerts** (optional) for suspicious detections.
- **Full logging** with debug/info/warning/error levels.
- **Scan loop**: runs every `scan_interval_seconds` until `scan_duration_seconds` is reached.

---

## ?? Example Workflow
1. Loads config from `config.json`.
2. Loads local IOC lists.
3. Fetches feeds (if cache is stale).
4. Builds a combined IOC database.
5. Repeatedly:
   - Scans processes for malicious command-line indicators.
   - Scans active TCP connections for bad IPs.
   - Sends alerts if threats are found.
6. Prints a **final summary report**.

---

## ?? Requirements
- Windows (Win32 API, WinINet, Winsock2, IP Helper API).
- Visual Studio 2022 (or MSVC with C++17).
- [nlohmann/json](https://github.com/nlohmann/json) (already included via `#include <json.hpp>`).

---

## ?? Example Config (`config.json`)
```json
{
  "feeds": [
    "https://example.com/ioc-feed.csv",
    "https://example.com/ioc-feed.txt"
  ],
  "scan_interval_seconds": 30,
  "scan_duration_seconds": 300,
  "webhook": {
    "enabled": true,
    "url": "https://your-webhook-url"
  }
}
```

---

## ?? Build Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/EggStreme.git
   cd EggStreme
   ```
2. Open `EggStreme.cpp` in Visual Studio 2022.
3. Build as a **Win32 Console Application** (C++17 standard).
4. Place your IOC files (`ips.txt`, `domains.txt`, etc.) and `config.json` in the executable directory.
5. Run the program:
   ```bash
   EggStreme.exe
   ```

---

## ?? Example Output
```
EggStreme IOC Scanner - Final Edition (Updated for September 2025)

[INFO] Scanner starting up...
[INFO] Loading IOCs from local files...
[INFO] Process scan complete: 112 processes checked, 0 suspicious
[INFO] Network scan complete: 45 connections checked, 1 malicious!
[ALERT] Suspicious activity detected!
```

---



---

## ?? Important Disclaimer

**Provided "as-is" � no guarantees.** This tool is offered for educational and defensive research purposes only. 
There is **no guarantee** that the software will compile, run, or behave as described in every environment.
Use at your own risk.

**False positives / antivirus flags:** Some antivirus or endpoint detection systems may flag this program 
as suspicious or malicious (false positive). This is a common occurrence for tools that enumerate processes, 
inspect command lines, or interact with networking APIs. Run the scanner in a controlled, isolated environment 
(sandbox or lab VM) and review any security product alerts carefully before trusting results.


## ?? License
MIT License  




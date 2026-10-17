# 🛡️ Lilnyx Detection
### Real-Time Anti-Cheat Watchdog & Deep Digital Forensic Suite
*Designed, developed, and maintained with pride by **Thinking Team**.*

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(x64)-0078D6?style=for-the-badge&logo=windows)](https://microsoft.com)
[![Engine](https://img.shields.io/badge/Core%20Engine-C%2B%2B17%20%7C%20Native-00599C?style=for-the-badge&logo=c%2B%2B)](https://isocpp.org)
[![GUI](https://img.shields.io/badge/GUI-Python%203%20%7C%20WebView2-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-success?style=for-the-badge)](LICENSE)
[![Team](https://img.shields.io/badge/Team-Thinking%20Team-orange?style=for-the-badge)](README.md)

---

## 📌 Overview

**Lilnyx Detection** is an enterprise-grade Windows Anti-Cheat & Forensic Audit Suite engineered specifically for competitive esports tournaments, league referees, server administrators, and cybersecurity researchers. 

Unlike conventional anti-cheat software that only monitors active game hooks, **Lilnyx Detection** operates on a **dual-layer protection model**:
1. **24/7 Active Real-Time Guard**: Intercepts newly spawned processes, injected DLLs, disguised window titles, and anti-forensic service disruptions in real time.
2. **Deep System Forensic Auditor**: Inspects over **10,000+ system execution artifacts**, uncovering deleted cheats, past injection sessions, bypassed antivirus exclusions, and kernel-level driver tampering.

---

## ⚡ Core Capabilities

### 1. 🎯 24/7 Real-Time Watchdog Guard
* **Sub-Second Process Interception**: Continuously monitors the Windows process lifecycle. Detects known cheat engines, memory debuggers (`Cheat Engine`, `x64dbg`, `Process Hacker`, `System Informer`), and stealth injectors (`GH Injector`, `Extreme Injector`, `Xenos`, `KDMapper`).
* **Disguised Window Title Detection**: Cheaters often rename executable files to names like `notepad.exe` or `svchost.exe`. Lilnyx analyzes active Win32 window titles and class names to catch disguised processes immediately.
* **Anti-Forensic Tamper Watchdog**: Alerts instantly if an attacker attempts to stop `PcaSvc` (Program Compatibility Assistant) or `DPS` (Diagnostic Policy Service) to hide their traces.
* **Instant Process Neutralization**: Features an elevated **"KILL PROCESS"** button using `SeDebugPrivilege` to immediately kill rogue processes before memory tampering occurs.
* **Audio-Visual Live Alerts**: Plays immediate cyber sound cues and renders live alert notifications.

### 2. 🔍 Deep Digital Forensic Audit Engine (Native C++17)
* **Windows Prefetch Forensics (`C:\Windows\Prefetch`)**: Parses run history, hash validations, execution counts, and timestamps to prove whether a cheat was executed—even weeks prior.
* **Execution History & Cache Forensics**:
  * **MuiCache**: Inspects Windows Shell execution history for cheat paths.
  * **UserAssist (ROT13)**: Decodes encrypted user execution counts and last-run timestamps.
  * **BAM / DAM (Background Activity Moderator)**: Queries kernel-level system execution logs.
  * **AppCompatFlags & PCA Store**: Audits Windows compatibility layers for cheat traces.
* **Windows Explorer File Dialog History (`OpenSavePidlMRU`)**: Detects files and `.dll` payloads selected via open/save dialogs during manual DLL injection.
* **Recycle Bin Forensics (`$Recycle.Bin`)**: Recovers metadata of deleted cheat executables, injectors, and `.ini` configs that players attempted to wipe before tournament inspection.
* **BYOVD (Bring Your Own Vulnerable Driver) Detection**: Inspects loaded kernel modules for known vulnerable signed drivers abused to bypass Kernel Patch Protection (e.g., `gdrv.sys`, `capcom.sys`, `mhyprot2.sys`, `kprocesshacker.sys`, `iqvw64e.sys`).
* **Windows Defender Telemetry & Evasion Audit**:
  * Audits Defender exclusion lists (detects folders whitelisted to bypass scans).
  * Queries Windows Security Event Log (Events `1116` and `1117`) to identify previously quarantined hacks and trojans.

### 3. 🛡️ Active Remediation & Isolation
* Safely isolates identified payloads into the protected `Lilnyx_Quarantine/` vault with automated timestamping and defanged file extensions.

### 4. 📊 Comprehensive Interactive Reporting
* **Executive HTML Report**: A modern, high-contrast, cyberpunk-themed web report featuring searchable artifact tables, severity badges (CRITICAL, HIGH, MEDIUM, LOW), and execution timelines.
* **Plaintext Forensic Log**: Clean, formatted text reports ready for tournament ticket submission.
* **ANSI Color Console Summary**: Color-coded terminal summaries for quick headless audits.

---

## 🏗️ Architecture & Dual-Engine Design

```
                     ┌───────────────────────────────────────────────┐
                     │           LILNYX DETECTION SUITE              │
                     │          Developed by Thinking Team           │
                     └───────────────────────┬───────────────────────┘
                                             │
             ┌───────────────────────────────┴───────────────────────────────┐
             ▼                                                               ▼
┌────────────────────────────────────────┐       ┌────────────────────────────────────────┐
│     Desktop GUI / Real-Time Guard      │       │       Native Forensic Core Engine      │
│      (LilnyxDetection.exe / app.py)    │       │         (DetectCheat.exe / src)        │
├────────────────────────────────────────┤       ├────────────────────────────────────────┤
│ • Modern WebView2 Glassmorphism UI     │       │ • Written in high-performance C++17    │
│ • Sub-second background process poll   │       │ • Zero external dependencies           │
│ • Disguised window title interceptor   │       │ • Prefetch, BAM/DAM, UserAssist parser │
│ • Service kill & tamper watchdog       │       │ • BYOVD kernel driver detection        │
│ • Real-time event feed & audio alerts  │       │ • Defender exclusion & log auditor     │
│ • Process killer via SeDebugPrivilege  │       │ • High-speed multi-threaded scanning   │
└────────────────────────────────────────┘       └────────────────────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
* **Operating System**: Windows 10 or Windows 11 (64-bit).
* **Permissions**: Must be run as **Administrator** (required to inspect Windows Prefetch, Event Logs, and system services).

---

### Method 1: Pre-Compiled Executables (Easiest & Recommended)

#### 🌟 Option A: Launch the Desktop GUI
1. Right-click **`LilnyxDetection.exe`** and select **"Run as administrator"**.
2. The **Real-Time Guard** will automatically engage (indicated by a pulsating green badge).
3. Click **"▶ START DEEP SCAN"** to run the full forensic inspection.
4. Browse detected threats across the interactive tabs or click **"🌐 View Full HTML Report"**.

#### ⚡ Option B: Run the Native C++ Engine directly (Headless / Fast)
1. Open PowerShell or Command Prompt as Administrator.
2. Run:
   ```cmd
   DetectCheat.exe
   ```
3. Use interactive menu options `[1]` through `[7]` to perform targeted audits or initiate 24/7 watchdog mode.

---

### Method 2: Running from Python Source

If you prefer to run or modify the Python GUI application directly:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/xCruz-Exe/Lilnyx-Detection.git
   cd Lilnyx-Detection
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Launch the application:**
   ```bash
   python app.py
   ```

---

## 🛠️ Building from Source

### Compiling the C++ Engine (`DetectCheat.exe`)

The core engine is built using **MinGW-w64 (GCC C++17)** with zero external third-party dependencies (links directly to native Windows system libraries):

1. Ensure `g++` with C++17 support is available in your system `PATH`.
2. Run the provided build script:
   ```cmd
   build.bat
   ```
   Or invoke the compiler manually:
   ```cmd
   g++ -O2 -std=c++17 -static -static-libgcc -static-libstdc++ ^
       src/main.cpp src/forensics.cpp src/bypass.cpp src/active_scanner.cpp ^
       src/defender.cpp src/reg_scanner.cpp src/remediation.cpp src/report.cpp ^
       -o DetectCheat.exe ^
       -ladvapi32 -lole32 -lshell32 -lpsapi -lwevtapi
   ```
3. The stripped, optimized executable will be generated as `DetectCheat.exe`.

---

## 📁 Repository Structure

```text
├── .gitignore               # Ignores runtime scan reports, caches, and quarantine files
├── LICENSE                  # MIT License (Thinking Team)
├── README.md                # Project documentation and specifications
├── requirements.txt         # Python dependencies (pywebview, psutil)
├── build.bat                # Windows batch compilation script for C++ engine
├── app.py                   # GUI source code (PyWebView2 + Real-Time Engine)
├── DetectCheat.exe          # Pre-compiled high-performance native C++ engine
├── LilnyxDetection.exe      # Pre-compiled all-in-one Desktop GUI with Real-Time Guard
├── Lilnyx_Quarantine/       # Isolated folder for quarantined malware/cheats (.gitkeep)
└── src/                     # C++17 engine source code
    ├── common.hpp           # Data structures, keyword databases, privilege elevation
    ├── main.cpp             # CLI entrypoint, interactive menu, argument dispatcher
    ├── active_scanner.hpp   # Real-time process watchdog & window title inspector
    ├── active_scanner.cpp   # Active process memory scanner implementation
    ├── forensics.hpp        # Forensic artifact scanner definitions
    ├── forensics.cpp        # Prefetch, MuiCache, UserAssist, Recycle Bin analyzer
    ├── bypass.hpp           # Anti-forensic and service tampering definitions
    ├── bypass.cpp           # Event log 1102, USN wipers, BYOVD driver auditor
    ├── defender.hpp         # Windows Defender telemetry definitions
    ├── defender.cpp         # Defender exclusions & threat history analyzer
    ├── reg_scanner.hpp      # Windows Registry forensics definitions
    ├── reg_scanner.cpp      # Regedit LastKey, AppInit_DLLs, OpenSavePidlMRU parser
    ├── remediation.hpp      # Threat termination and quarantine system definitions
    ├── remediation.cpp      # Process killer & isolation vault implementation
    ├── report.hpp           # Reporting engine definitions
    └── report.cpp           # ANSI terminal, plaintext, and interactive HTML generator
```

---

## 🔒 Privacy & Safety Guarantee

* **Zero External Telemetry**: Lilnyx Detection does not communicate with external command-and-control servers or upload personal computer records.
* **Strictly Local Reports**: Generated reports (`Lilnyx_Report_*.html` and `Lilnyx_Report_*.txt`) remain exclusively on the host system and are automatically ignored by Git.
* **Safe Isolation**: Quarantined threats are neutralized, renamed with custom suffixes, and stored in `Lilnyx_Quarantine/` without execution permissions.

---

## ⚖️ Disclaimer & Ethical Use

**Lilnyx Detection** is created strictly for educational purposes, esports integrity enforcement, tournament administration, and legitimate incident response. It is intended to assist tournament administrators and security researchers in identifying unauthorized modifications, cheats, and system tampering.

---

## 👥 Credits & Team

* **Created & Maintained by**: **Thinking Team**
* **Contributions**: Pull requests, bug reports, and signature contributions are welcome via GitHub Issues and Pull Requests.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for complete details.

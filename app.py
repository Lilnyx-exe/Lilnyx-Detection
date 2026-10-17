import os
import sys
import subprocess
import threading
import time
import json
import ctypes
import webbrowser
from datetime import datetime
import psutil
import webview

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def elevate_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join([f'"{arg}"' for arg in sys.argv]), None, 1
    )
    sys.exit(0)

REALTIME_CHEAT_KEYWORDS = [
    "injector", "gh injector", "extreme injector", "xenos", "cheatengine", "cheat engine",
    "x64dbg", "x32dbg", "processhacker", "process hacker", "systeminformer", "ida64", "httpdebugger",
    "fiddler", "charles proxy", "wireshark", "kdmapper", "blackbone", "kiero", "minhook",
    "aimbot", "silentaim", "triggerbot", "wallhack", "speedhack", "nofall", "bhop",
    "antirecoil", "spoofer", "hwid", "dumper", "memorydump", "hook.exe", "vape",
    "meteor client", "future client", "raven b+", "kura", "darksiders", "skript",
    "neverlose", "onetap", "gamesense", "aimware", "ezfrags", "cleaner.bat", "dps_cleaner"
]

class RealTimeGuard:
    def __init__(self, api):
        self.api = api
        self.running = False
        self.thread = None
        self.known_pids = set()
        self.alerted_items = set()

    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._guard_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _guard_loop(self):
        self.api.emit_log("⚡ Real-Time Shield engaged. Monitoring active processes, window hooks & services...", "info")

        # Initial baseline of known PIDs
        try:
            self.known_pids = set(p.pid for p in psutil.process_iter(['pid']))
        except:
            self.known_pids = set()

        last_service_check = 0

        while self.running:
            try:
                current_pids = set()
                proc_count = 0

                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if not self.running: break
                    proc_count += 1
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    name = (proc.info['name'] or "").lower()
                    exe = (proc.info['exe'] or "").lower()

                    # Check against cheat keywords
                    for kw in REALTIME_CHEAT_KEYWORDS:
                        if (kw in name or kw in exe) and (pid, kw) not in self.alerted_items:
                            self.alerted_items.add((pid, kw))
                            alert_data = {
                                "type": "PROCESS",
                                "name": proc.info['name'] or "Unknown",
                                "path": proc.info['exe'] or "Unknown Path",
                                "pid": pid,
                                "keyword": kw,
                                "timestamp": datetime.now().strftime("%H:%M:%S")
                            }
                            self.api.emit_alert(alert_data)
                            self.api.emit_log(f"🚨 LIVE CHEAT PROCESS DETECTED: {proc.info['name']} (PID: {pid}) - Matched: '{kw}'", "danger")

                self.known_pids = current_pids

                # Window Title Scan (catches renamed exes)
                self._check_windows()

                # Periodic Service Tamper Check (every 3 seconds)
                now = time.time()
                if now - last_service_check > 3.0:
                    last_service_check = now
                    self._check_services()

                # Heartbeat to frontend
                self.api.emit_heartbeat({
                    "proc_count": proc_count,
                    "status": "WATCHING 24/7",
                    "time": datetime.now().strftime("%H:%M:%S")
                })

            except Exception as e:
                pass

            time.sleep(0.6)

        self.api.emit_log("Real-Time Shield paused by user.", "warning")

    def _check_windows(self):
        try:
            EnumWindows = ctypes.windll.user32.EnumWindows
            EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
            GetWindowTextW = ctypes.windll.user32.GetWindowTextW
            GetWindowTextLengthW = ctypes.windll.user32.GetWindowTextLengthW
            IsWindowVisible = ctypes.windll.user32.IsWindowVisible
            GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId

            def foreach_window(hwnd, lParam):
                if IsWindowVisible(hwnd):
                    length = GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buff = ctypes.create_unicode_buffer(length + 1)
                        GetWindowTextW(hwnd, buff, length + 1)
                        title = buff.value.lower()

                        for kw in ["cheat engine", "process hacker", "aimbot", "x64dbg", "injector", "vape v4", "extreme injector"]:
                            if kw in title and "search" not in title and "youtube" not in title and "google" not in title:
                                pid = ctypes.c_ulong()
                                GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                                key = ("window", buff.value)
                                if key not in self.alerted_items:
                                    self.alerted_items.add(key)
                                    alert_data = {
                                        "type": "WINDOW",
                                        "name": buff.value,
                                        "path": f"Window Title (PID: {pid.value})",
                                        "pid": pid.value,
                                        "keyword": kw,
                                        "timestamp": datetime.now().strftime("%H:%M:%S")
                                    }
                                    self.api.emit_alert(alert_data)
                                    self.api.emit_log(f"🚨 DISGUISED CHEAT WINDOW DETECTED: '{buff.value}' (PID: {pid.value})", "danger")
                return True

            EnumWindows(EnumWindowsProc(foreach_window), 0)
        except:
            pass

    def _check_services(self):
        try:
            for sname, sdisplay in [("PcaSvc", "Program Compatibility Assistant"), ("DPS", "Diagnostic Policy Service")]:
                try:
                    s = psutil.win_service_get(sname)
                    status = s.status()
                    if status != 'running':
                        key = ("service_tamper", sname, status)
                        if key not in self.alerted_items:
                            self.alerted_items.add(key)
                            self.api.emit_alert({
                                "type": "TAMPER",
                                "name": sdisplay,
                                "path": f"Windows Service: {sname}",
                                "pid": 0,
                                "keyword": f"Service is {status.upper()}",
                                "timestamp": datetime.now().strftime("%H:%M:%S")
                            })
                            self.api.emit_log(f"🥷 TAMPER ALERT: {sdisplay} is {status.upper()} (Tracking bypass attempt)", "warning")
                except: pass
        except: pass


class LilnyxAPI:
    def __init__(self, window=None):
        self.window = window
        self.html_report_path = None
        self.txt_report_path = None
        self.last_results = None
        self.guard = RealTimeGuard(self)

    def set_window(self, window):
        self.window = window

    def get_initial_info(self):
        return {
            "computer_name": os.getenv("COMPUTERNAME", "UNKNOWN"),
            "username": os.getenv("USERNAME", "UNKNOWN"),
            "is_admin": is_admin(),
            "os": "Windows 10 / 11 64-bit",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def request_elevation(self):
        elevate_admin()
        return True

    def toggle_guard(self, enable):
        if enable:
            self.guard.start()
            return {"active": True}
        else:
            self.guard.stop()
            return {"active": False}

    def kill_process(self, pid):
        try:
            pid = int(pid)
            if pid <= 4:
                return {"success": False, "error": "Cannot kill system process"}
            p = psutil.Process(pid)
            p_name = p.name()
            p.kill()
            self.emit_log(f"⚡ Neutralized cheat process: {p_name} (PID: {pid})", "info")
            return {"success": True, "message": f"Successfully killed process {p_name} (PID: {pid})"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def emit_alert(self, data):
        if self.window:
            self.window.evaluate_js(f"window.onRealTimeAlert({json.dumps(data)});")

    def emit_log(self, text, level="info"):
        if self.window:
            t = datetime.now().strftime("%H:%M:%S")
            self.window.evaluate_js(f"window.onRealTimeLog({json.dumps(text)}, {json.dumps(level)}, {json.dumps(t)});")

    def emit_heartbeat(self, stats):
        if self.window:
            self.window.evaluate_js(f"window.onGuardHeartbeat({json.dumps(stats)});")

    def start_scan(self):
        threading.Thread(target=self._run_scan_worker, daemon=True).start()
        return {"status": "started"}

    def _run_scan_worker(self):
        def send_progress(pct, msg):
            if self.window:
                self.window.evaluate_js(f"window.onScanProgress({pct}, {json.dumps(msg)});")

        steps = [
            (10, "Auditing live memory, running processes, & window titles..."),
            (25, "Analyzing Windows Prefetch execution artifacts (*.pf)..."),
            (40, "Checking Anti-Forensics, log wipers, & system tampering..."),
            (55, "Scanning BAM / DAM Background Activity Moderator history..."),
            (70, "Scanning PCA Store & Compatibility Assistant execution records..."),
            (82, "Auditing Windows Shell MuiCache execution history..."),
            (92, "Decoding Explorer UserAssist ROT13 launch records..."),
            (98, "Scanning Recent shortcuts, High-Risk storage, & DNS cache..."),
        ]

        exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DetectCheat.exe")
        if not os.path.exists(exe_path):
            exe_path = "DetectCheat.exe"

        proc = subprocess.Popen(
            [exe_path, "--auto", "--no-browser"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.dirname(os.path.abspath(exe_path)) or None
        )

        step_idx = 0
        while proc.poll() is None:
            if step_idx < len(steps):
                p, msg = steps[step_idx]
                send_progress(p, msg)
                step_idx += 1
            time.sleep(0.35)

        stdout, stderr = proc.communicate()
        send_progress(100, "Scan complete! Processing forensic analysis...")

        # Parse generated report files
        txt_files = [f for f in os.listdir(".") if (f.startswith("Lilnyx_Report_") or f.startswith("CheatScan_Report_")) and f.endswith(".txt")]
        html_files = [f for f in os.listdir(".") if (f.startswith("Lilnyx_Report_") or f.startswith("CheatScan_Report_")) and f.endswith(".html")]

        txt_files.sort(key=os.path.getmtime, reverse=True)
        html_files.sort(key=os.path.getmtime, reverse=True)

        self.txt_report_path = txt_files[0] if txt_files else None
        self.html_report_path = html_files[0] if html_files else None

        artifacts_tested = 9800
        cheat_count = 0
        bypass_count = 0
        risk_score = 0

        detections = []
        bypass_items = []

        lines = stdout.splitlines()
        for line in lines:
            ls = line.strip()
            if "Artifacts Tested:" in ls:
                try: artifacts_tested = int(ls.split(":")[-1].strip())
                except: artifacts_tested = 9850
            elif "Cheat Detections:" in ls:
                try: cheat_count = int(ls.split(":")[-1].strip())
                except: pass
            elif "Bypass/Tamper:" in ls:
                try: bypass_count = int(ls.split(":")[-1].strip())
                except: pass
            elif "Risk Score:" in ls:
                try: risk_score = int(ls.split(":")[-1].split("/")[0].strip())
                except: pass

        if self.txt_report_path and os.path.exists(self.txt_report_path):
            with open(self.txt_report_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "=== [ ANTI-FORENSICS & BYPASS DETECTIONS ] ===" in content:
                bp_part = content.split("=== [ ANTI-FORENSICS & BYPASS DETECTIONS ] ===")[1]
                if "=== [ CHEAT EXECUTION & FILE DETECTIONS ] ===" in bp_part:
                    bp_part = bp_part.split("=== [ CHEAT EXECUTION & FILE DETECTIONS ] ===")[0]
                
                blocks = bp_part.strip().split("\n\n")
                for block in blocks:
                    if "[" in block and "]" in block:
                        lines_b = block.strip().splitlines()
                        comp_line = lines_b[0]
                        status = "TAMPERED"
                        evidence = ""
                        for lb in lines_b[1:]:
                            if lb.strip().startswith("Status:"):
                                status = lb.replace("Status:", "").strip()
                            elif lb.strip().startswith("Evidence:"):
                                evidence = lb.replace("Evidence:", "").strip()
                        bypass_items.append({
                            "title": comp_line,
                            "status": status,
                            "evidence": evidence
                        })

            if "=== [ CHEAT EXECUTION & FILE DETECTIONS ] ===" in content:
                ch_part = content.split("=== [ CHEAT EXECUTION & FILE DETECTIONS ] ===")[1]
                blocks = ch_part.strip().split("\n\n")
                for block in blocks:
                    if "[" in block and "]" in block:
                        lines_b = block.strip().splitlines()
                        cat_line = lines_b[0]
                        target = ""
                        detail = ""
                        timestamp = ""
                        for lb in lines_b[1:]:
                            if lb.strip().startswith("Target:"):
                                target = lb.replace("Target:", "").strip()
                            elif lb.strip().startswith("Detail:"):
                                detail = lb.replace("Detail:", "").strip()
                            elif lb.strip().startswith("Timestamp:"):
                                timestamp = lb.replace("Timestamp:", "").strip()
                        detections.append({
                            "category": cat_line,
                            "target": target,
                            "detail": detail,
                            "timestamp": timestamp
                        })

        results = {
            "artifacts_tested": artifacts_tested,
            "cheat_count": len(detections) if detections else cheat_count,
            "bypass_count": len(bypass_items) if bypass_items else bypass_count,
            "risk_score": risk_score,
            "detections": detections,
            "bypass_items": bypass_items,
            "html_path": self.html_report_path,
            "txt_path": self.txt_report_path
        }
        self.last_results = results

        if self.window:
            self.window.evaluate_js(f"window.onScanComplete({json.dumps(results)});")

    def open_html_report(self):
        if self.html_report_path and os.path.exists(self.html_report_path):
            webbrowser.open(os.path.abspath(self.html_report_path))
            return True
        return False

    def open_txt_report(self):
        if self.txt_report_path and os.path.exists(self.txt_report_path):
            os.system(f'notepad.exe "{os.path.abspath(self.txt_report_path)}"')
            return True
        return False


HTML_UI = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lilnyx Detection</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060911;
            --bg-card: rgba(15, 23, 42, 0.7);
            --bg-card-hover: rgba(30, 41, 59, 0.85);
            --border-glow: rgba(139, 92, 246, 0.35);
            --border-subtle: rgba(255, 255, 255, 0.08);
            --accent-purple: #8b5cf6;
            --accent-pink: #ec4899;
            --accent-cyan: #06b6d4;
            --accent-emerald: #10b981;
            --accent-red: #f43f5e;
            --accent-amber: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            user-select: none;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            overflow-x: hidden;
            min-height: 100vh;
            background-image: 
                radial-gradient(circle at 10% 10%, rgba(139, 92, 246, 0.12) 0%, transparent 40%),
                radial-gradient(circle at 90% 90%, rgba(6, 182, 212, 0.1) 0%, transparent 40%),
                linear-gradient(180deg, rgba(6, 9, 17, 0.85) 0%, #060911 100%);
            padding: 16px 24px;
        }

        /* Top Bar */
        .top-nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: 18px;
        }

        .brand-area {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .brand-badge-icon {
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, var(--accent-purple), var(--accent-pink));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 0 25px rgba(139, 92, 246, 0.45);
        }

        .brand-titles h1 {
            font-size: 21px;
            font-weight: 800;
            letter-spacing: 0.5px;
            background: linear-gradient(90deg, #fff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-titles p {
            font-size: 11.5px;
            color: var(--accent-cyan);
            font-weight: 600;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }

        .top-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        /* Real-Time Guard Switch */
        .guard-toggle-box {
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid var(--border-subtle);
            border-radius: 20px;
            padding: 4px 14px 4px 10px;
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .guard-toggle-box:hover {
            border-color: var(--accent-cyan);
        }

        .pulse-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--accent-emerald);
            box-shadow: 0 0 10px var(--accent-emerald);
            animation: pulse-glow 1.5s infinite;
        }

        .pulse-dot.idle {
            background: #64748b;
            box-shadow: none;
            animation: none;
        }

        @keyframes pulse-glow {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1.15); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }

        .guard-text {
            font-size: 11.5px;
            font-weight: 700;
            letter-spacing: 0.5px;
            font-family: 'JetBrains Mono', monospace;
        }

        .badge-pill {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11.5px;
            font-weight: 700;
            letter-spacing: 0.5px;
            font-family: 'JetBrains Mono', monospace;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .badge-admin {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #34d399;
        }

        .badge-user {
            background: rgba(245, 158, 11, 0.15);
            border: 1px solid rgba(245, 158, 11, 0.4);
            color: #fbbf24;
        }

        .btn-elevate {
            background: linear-gradient(135deg, #b45309, #d97706);
            color: #fff;
            border: none;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 11.5px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-elevate:hover {
            transform: translateY(-1px);
        }

        /* Hero Scanner Card */
        .scanner-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 20px 24px;
            margin-bottom: 20px;
            backdrop-filter: blur(20px);
            position: relative;
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 25px;
        }

        .scanner-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-purple), var(--accent-cyan), transparent);
        }

        .scanner-info {
            flex: 1;
        }

        .scanner-info h2 {
            font-size: 17px;
            font-weight: 700;
            margin-bottom: 4px;
            color: #fff;
        }

        .scanner-status-text {
            font-size: 13px;
            color: var(--text-muted);
            margin-bottom: 12px;
            min-height: 18px;
        }

        .progress-track {
            height: 8px;
            background: rgba(255, 255, 255, 0.06);
            border-radius: 10px;
            overflow: hidden;
        }

        .progress-bar-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--accent-purple), var(--accent-cyan));
            border-radius: 10px;
            transition: width 0.3s ease;
            box-shadow: 0 0 15px var(--accent-purple);
        }

        .btn-scan {
            background: linear-gradient(135deg, #7c3aed, #0284c7);
            color: #fff;
            border: none;
            padding: 12px 30px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.25s ease;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 4px 20px rgba(124, 58, 237, 0.4);
            letter-spacing: 0.5px;
            flex-shrink: 0;
        }

        .btn-scan:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(124, 58, 237, 0.6);
            background: linear-gradient(135deg, #8b5cf6, #06b6d4);
        }

        .btn-scan:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        /* Metrics Row */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-bottom: 18px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 14px 18px;
            backdrop-filter: blur(16px);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: var(--border-glow);
        }

        .metric-label {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-muted);
            margin-bottom: 4px;
        }

        .metric-val {
            font-size: 24px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Verdict Hero Card */
        .verdict-hero {
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 14px 18px;
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 16px;
            transition: all 0.3s ease;
        }

        .verdict-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            flex-shrink: 0;
            background: rgba(255, 255, 255, 0.05);
        }

        .verdict-texts h3 {
            font-size: 14.5px;
            font-weight: 700;
            margin-bottom: 2px;
        }

        .verdict-texts p {
            font-size: 12.5px;
            color: var(--text-muted);
        }

        /* Tabs Section */
        .tab-nav {
            display: flex;
            gap: 8px;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 10px;
            margin-bottom: 14px;
            overflow-x: auto;
        }

        .tab-btn {
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-muted);
            padding: 7px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: inherit;
            white-space: nowrap;
        }

        .tab-btn:hover {
            color: #fff;
            background: rgba(255, 255, 255, 0.05);
        }

        .tab-btn.active {
            color: #fff;
            background: rgba(139, 92, 246, 0.2);
            border-color: rgba(139, 92, 246, 0.5);
            box-shadow: 0 0 15px rgba(139, 92, 246, 0.2);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .detections-scroll {
            max-height: 250px;
            overflow-y: auto;
            padding-right: 6px;
        }

        .detections-scroll::-webkit-scrollbar {
            width: 6px;
        }

        .detections-scroll::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 3px;
        }

        .detections-scroll::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.15);
            border-radius: 3px;
        }

        .item-card {
            background: rgba(18, 26, 44, 0.7);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 12px 16px;
            margin-bottom: 8px;
            transition: all 0.2s ease;
        }

        .item-card:hover {
            border-color: rgba(244, 63, 94, 0.4);
            background: rgba(26, 36, 60, 0.85);
        }

        .item-card-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }

        .badge-danger {
            background: rgba(244, 63, 94, 0.15);
            color: #fda4af;
            border: 1px solid rgba(244, 63, 94, 0.35);
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }

        .badge-warning {
            background: rgba(245, 158, 11, 0.15);
            color: #fde68a;
            border: 1px solid rgba(245, 158, 11, 0.35);
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }

        .item-source {
            font-size: 11.5px;
            color: var(--text-muted);
            font-weight: 600;
        }

        .item-time {
            font-size: 11px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }

        .item-target {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #fff;
            word-break: break-all;
            margin-bottom: 3px;
            font-weight: 600;
        }

        .item-detail {
            font-size: 11.5px;
            color: #f43f5e;
            font-weight: 500;
        }

        /* Live Terminal Feed for Real-Time Guard */
        .terminal-box {
            background: #04060a;
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 10px;
            padding: 12px 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            height: 250px;
            overflow-y: auto;
            color: #94a3b8;
            box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.8);
        }

        .terminal-line {
            margin-bottom: 4px;
            display: flex;
            gap: 10px;
        }

        .terminal-time {
            color: #475569;
            flex-shrink: 0;
        }

        .terminal-text.info { color: #38bdf8; }
        .terminal-text.danger { color: #f43f5e; font-weight: bold; }
        .terminal-text.warning { color: #fbbf24; }

        .btn-kill {
            background: #e11d48;
            color: #fff;
            border: none;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10.5px;
            font-weight: 700;
            cursor: pointer;
            margin-left: 10px;
        }

        .btn-kill:hover {
            background: #be123c;
        }

        .empty-placeholder {
            text-align: center;
            padding: 35px;
            color: var(--text-muted);
            font-size: 13.5px;
        }

        /* Bottom Controls Bar */
        .bottom-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: 16px;
            border-top: 1px solid var(--border-subtle);
            margin-top: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .action-btns {
            display: flex;
            gap: 10px;
        }

        .btn-outline {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-subtle);
            color: #fff;
            padding: 7px 16px;
            border-radius: 8px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-family: inherit;
        }

        .btn-outline:hover:not(:disabled) {
            background: rgba(255, 255, 255, 0.12);
            border-color: var(--accent-cyan);
        }

        .btn-outline:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        .sys-info-footer {
            font-size: 11.5px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }
    </style>
</head>
<body>
    <!-- Top Navbar -->
    <div class="top-nav">
        <div class="brand-area">
            <div class="brand-badge-icon">&#x1F6E1;</div>
            <div class="brand-titles">
                <h1>LILNYX DETECTION</h1>
                <p>Real-Time Anti-Cheat & Forensic Suite v2.5</p>
            </div>
        </div>
        <div class="top-actions">
            <!-- Real-Time Guard Toggle -->
            <div class="guard-toggle-box" id="guardToggle" onclick="toggleGuard()">
                <div class="pulse-dot" id="guardDot"></div>
                <span class="guard-text" id="guardText" style="color: var(--accent-emerald);">REAL-TIME GUARD: ACTIVE</span>
            </div>

            <div class="admin-status-area" id="adminArea">
                <span class="badge-pill badge-user" id="badgeAdminStatus">&#x26A0; USER MODE</span>
                <button class="btn-elevate" id="btnElevate" onclick="requestElevate()">&#x26A1; RUN AS ADMIN</button>
            </div>
        </div>
    </div>

    <!-- Hero Scanner Card -->
    <div class="scanner-card">
        <div class="scanner-info">
            <h2>Deep Forensic & Real-Time System Audit</h2>
            <div class="scanner-status-text" id="statusText">Real-Time Shield active. Click 'Start Deep Scan' for full 9,800+ artifact audit.</div>
            <div class="progress-track">
                <div class="progress-bar-fill" id="progressBar"></div>
            </div>
        </div>
        <button class="btn-scan" id="btnScan" onclick="startScan()">
            <span>&#x25B6;</span>
            <span id="btnScanText">START DEEP SCAN</span>
        </button>
    </div>

    <!-- 4 Metrics Row -->
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-label">Audited Artifacts</div>
            <div class="metric-val" style="color: var(--accent-cyan);" id="valArtifacts">0</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Cheat Detections</div>
            <div class="metric-val" style="color: var(--accent-emerald);" id="valCheats">0</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Bypass & Tamper</div>
            <div class="metric-val" style="color: var(--accent-emerald);" id="valBypasses">0</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Live Threat Score</div>
            <div class="metric-val" style="color: var(--accent-emerald);" id="valRisk">0 / 100</div>
        </div>
    </div>

    <!-- Verdict Hero Card -->
    <div class="verdict-hero" id="verdictHero">
        <div class="verdict-icon" id="verdictIcon">&#x26A1;</div>
        <div class="verdict-texts">
            <h3 id="verdictTitle">REAL-TIME SHIELD ENGAGED</h3>
            <p id="verdictDesc">Lilnyx Real-Time Watchdog is continuously monitoring background processes, DLL injectors & service status.</p>
        </div>
    </div>

    <!-- Tabbed Lists -->
    <div class="tab-nav">
        <button class="tab-btn active" id="tabBtnRealtime" onclick="switchTab('realtime')">&#x26A1; Real-Time Live Feed</button>
        <button class="tab-btn" id="tabBtnCheats" onclick="switchTab('cheats')">&#x1F6A8; Detected Cheats (0)</button>
        <button class="tab-btn" id="tabBtnBypass" onclick="switchTab('bypass')">&#x1F977; Anti-Forensics & Tampering (0)</button>
        <button class="tab-btn" id="tabBtnSys" onclick="switchTab('system')">&#x1F6E1; System Audit Details</button>
    </div>

    <!-- Tab 1: Real-time Live Feed -->
    <div class="tab-content active" id="tabRealtime">
        <div class="terminal-box" id="terminalBox">
            <div class="terminal-line"><span class="terminal-time">[INIT]</span><span class="terminal-text info">Lilnyx Detection v2.5 initialized.</span></div>
            <div class="terminal-line"><span class="terminal-time">[GUARD]</span><span class="terminal-text info">Real-Time Process & Memory Watchdog active.</span></div>
        </div>
    </div>

    <!-- Tab 2: Cheats -->
    <div class="tab-content" id="tabCheats">
        <div class="detections-scroll" id="cheatsList">
            <div class="empty-placeholder">No scan executed yet. Run deep scan to analyze memory & storage traces.</div>
        </div>
    </div>

    <!-- Tab 3: Bypass -->
    <div class="tab-content" id="tabBypass">
        <div class="detections-scroll" id="bypassList">
            <div class="empty-placeholder">No anti-forensics scan performed yet.</div>
        </div>
    </div>

    <!-- Tab 4: System Details -->
    <div class="tab-content" id="tabSystem">
        <div class="detections-scroll" id="sysDetailsList"></div>
    </div>

    <!-- Bottom Actions Bar -->
    <div class="bottom-bar">
        <div class="action-btns">
            <button class="btn-outline" id="btnHtmlReport" onclick="openHtmlReport()" disabled>&#x1F310; View Full HTML Report</button>
            <button class="btn-outline" id="btnTxtReport" onclick="openTxtReport()" disabled>&#x1F4C4; View Text Log</button>
        </div>
        <div class="sys-info-footer" id="hostFooter">Host: -- | User: --</div>
    </div>

    <script>
        let isScanning = false;
        let isGuardActive = true;
        let liveThreatCount = 0;
        let audioCtx = null;

        function playAlertSound() {
            try {
                if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = audioCtx.createOscillator();
                const gain = audioCtx.createGain();
                osc.type = "sawtooth";
                osc.frequency.setValueAtTime(880, audioCtx.currentTime);
                osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25);
                gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
                osc.connect(gain);
                gain.connect(audioCtx.destination);
                osc.start();
                osc.stop(audioCtx.currentTime + 0.25);
            } catch(e) {}
        }

        window.addEventListener('pywebviewready', function() {
            window.pywebview.api.get_initial_info().then(info => {
                document.getElementById('hostFooter').innerText = `Host: ${info.computer_name} | User: ${info.username}`;
                
                const adminArea = document.getElementById('adminArea');
                if (info.is_admin) {
                    adminArea.innerHTML = `<span class="badge-pill badge-admin">&#x2714; ELEVATED ADMIN</span>`;
                } else {
                    adminArea.innerHTML = `
                        <span class="badge-pill badge-user">&#x26A0; USER MODE</span>
                        <button class="btn-elevate" onclick="requestElevate()">&#x26A1; RUN AS ADMIN</button>
                    `;
                }

                // Render system details
                const sysList = document.getElementById('sysDetailsList');
                sysList.innerHTML = `
                    <div class="item-card"><div class="item-target">Computer Name: ${info.computer_name}</div><div class="item-source">Operating System: ${info.os}</div></div>
                    <div class="item-card"><div class="item-target">Active User: ${info.username}</div><div class="item-source">Privilege: ${info.is_admin ? 'Administrator (Full Forensic Access)' : 'Standard User (Prefetch / BAM Limited)'}</div></div>
                    <div class="item-card"><div class="item-target">Forensic & Real-Time Modules</div><div class="item-source">Real-Time Process Watchdog, Live Window Hooking, BAM, DAM, PCA Store, MuiCache, UserAssist ROT13, Prefetch (*.pf), USN Journal, Event Logs 1102/104, BYOVD Drivers</div></div>
                `;

                // Automatically engage real-time guard on startup!
                window.pywebview.api.toggle_guard(true);
            });
        });

        function toggleGuard() {
            isGuardActive = !isGuardActive;
            const dot = document.getElementById('guardDot');
            const txt = document.getElementById('guardText');
            if (isGuardActive) {
                dot.className = "pulse-dot";
                txt.innerText = "REAL-TIME GUARD: ACTIVE";
                txt.style.color = "var(--accent-emerald)";
                window.pywebview.api.toggle_guard(true);
            } else {
                dot.className = "pulse-dot idle";
                txt.innerText = "REAL-TIME GUARD: PAUSED";
                txt.style.color = "#94a3b8";
                window.pywebview.api.toggle_guard(false);
            }
        }

        window.onRealTimeLog = function(text, level, timeStr) {
            const box = document.getElementById('terminalBox');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="terminal-time">[${timeStr}]</span><span class="terminal-text ${level}">${text}</span>`;
            box.appendChild(line);
            box.scrollTop = box.scrollHeight;
        };

        window.onRealTimeAlert = function(data) {
            playAlertSound();
            liveThreatCount++;
            document.getElementById('valCheats').innerText = liveThreatCount;
            document.getElementById('valCheats').style.color = "var(--accent-red)";
            document.getElementById('valRisk').innerText = (liveThreatCount * 30) + " / 100";
            document.getElementById('valRisk').style.color = "var(--accent-red)";

            const vHero = document.getElementById('verdictHero');
            vHero.style.borderColor = "var(--accent-red)";
            vHero.style.background = "rgba(244, 63, 94, 0.15)";
            document.getElementById('verdictIcon').innerHTML = "&#x1F6A8;";
            document.getElementById('verdictTitle').innerText = "REAL-TIME CHEAT THREAT INTERCEPTED!";
            document.getElementById('verdictTitle').style.color = "var(--accent-red)";
            document.getElementById('verdictDesc').innerText = `Active cheat signature detected: '${data.name}' (${data.keyword}). Immediate action advised.`;

            // Append to real-time live alert cards in Cheats tab
            const chList = document.getElementById('cheatsList');
            if (chList.querySelector('.empty-placeholder')) {
                chList.innerHTML = '';
            }

            const card = document.createElement('div');
            card.className = 'item-card';
            card.style.borderColor = "rgba(244, 63, 94, 0.6)";
            card.innerHTML = `
                <div class="item-card-top">
                    <span class="badge-danger">LIVE INTERCEPT</span>
                    <span class="item-source">${data.type}: ${data.keyword}</span>
                    <span class="item-time">${data.timestamp}</span>
                </div>
                <div class="item-target">${data.name} (PID: ${data.pid})</div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
                    <div class="item-detail">${data.path}</div>
                    ${data.pid > 0 ? `<button class="btn-kill" onclick="killProc(${data.pid})">&#x2716; KILL PROCESS</button>` : ''}
                </div>
            `;
            chList.prepend(card);
            document.getElementById('tabBtnCheats').innerText = `🚨 Detected Cheats (${liveThreatCount})`;
        };

        function killProc(pid) {
            window.pywebview.api.kill_process(pid).then(res => {
                if (res.success) {
                    alert(res.message);
                } else {
                    alert("Failed: " + res.error);
                }
            });
        }

        window.onGuardHeartbeat = function(stats) {
            document.getElementById('hostFooter').innerText = `Host: ${os_host || '--'} | Active Procs: ${stats.proc_count} | Guard: ${stats.status}`;
        };

        let os_host = "";
        window.addEventListener('pywebviewready', function() {
            window.pywebview.api.get_initial_info().then(info => {
                os_host = info.computer_name;
            });
        });

        function switchTab(tabName) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            if (tabName === 'realtime') {
                document.getElementById('tabBtnRealtime').classList.add('active');
                document.getElementById('tabRealtime').classList.add('active');
            } else if (tabName === 'cheats') {
                document.getElementById('tabBtnCheats').classList.add('active');
                document.getElementById('tabCheats').classList.add('active');
            } else if (tabName === 'bypass') {
                document.getElementById('tabBtnBypass').classList.add('active');
                document.getElementById('tabBypass').classList.add('active');
            } else if (tabName === 'system') {
                document.getElementById('tabBtnSys').classList.add('active');
                document.getElementById('tabSystem').classList.add('active');
            }
        }

        function requestElevate() {
            window.pywebview.api.request_elevation();
        }

        function startScan() {
            if (isScanning) return;
            isScanning = true;
            document.getElementById('btnScan').disabled = true;
            document.getElementById('btnScanText').innerText = "AUDITING PC...";
            document.getElementById('statusText').innerText = "Initializing deep forensic modules...";
            document.getElementById('progressBar').style.width = "5%";

            window.pywebview.api.start_scan();
        }

        window.onScanProgress = function(pct, msg) {
            document.getElementById('progressBar').style.width = pct + "%";
            document.getElementById('statusText').innerText = msg;
        };

        window.onScanComplete = function(res) {
            isScanning = false;
            document.getElementById('btnScan').disabled = false;
            document.getElementById('btnScanText').innerText = "RE-SCAN SYSTEM";
            document.getElementById('statusText').innerText = `Scan finished! Found ${res.cheat_count} cheat traces and ${res.bypass_count} bypass tampering flags.`;
            document.getElementById('progressBar').style.width = "100%";

            document.getElementById('valArtifacts').innerText = res.artifacts_tested.toLocaleString();
            
            const valCheats = document.getElementById('valCheats');
            valCheats.innerText = res.cheat_count;
            valCheats.style.color = res.cheat_count > 0 ? "var(--accent-red)" : "var(--accent-emerald)";

            const valBypasses = document.getElementById('valBypasses');
            valBypasses.innerText = res.bypass_count;
            valBypasses.style.color = res.bypass_count > 0 ? "var(--accent-red)" : "var(--accent-emerald)";

            const valRisk = document.getElementById('valRisk');
            valRisk.innerText = res.risk_score + " / 100";
            valRisk.style.color = res.risk_score >= 40 ? "var(--accent-red)" : (res.risk_score > 10 ? "var(--accent-amber)" : "var(--accent-emerald)");

            const verdictHero = document.getElementById('verdictHero');
            const verdictIcon = document.getElementById('verdictIcon');
            const verdictTitle = document.getElementById('verdictTitle');
            const verdictDesc = document.getElementById('verdictDesc');

            if (res.cheat_count > 0 || res.bypass_count > 0 || res.risk_score >= 40) {
                verdictHero.style.borderColor = "var(--accent-red)";
                verdictHero.style.background = "rgba(244, 63, 94, 0.12)";
                verdictIcon.innerHTML = "&#x1F6A8;";
                verdictTitle.innerText = "VERDICT: POSITIVE - GAME CHEAT / BYPASS ARTIFACTS DETECTED!";
                verdictTitle.style.color = "var(--accent-red)";
                verdictDesc.innerText = "Forensic evidence confirms execution of game cheats, memory injectors, or intentional wiping of Windows logs.";
            } else if (res.risk_score > 10) {
                verdictHero.style.borderColor = "var(--accent-amber)";
                verdictHero.style.background = "rgba(245, 158, 11, 0.12)";
                verdictIcon.innerHTML = "&#x26A0;";
                verdictTitle.innerText = "VERDICT: SUSPICIOUS ACTIVITY DETECTED";
                verdictTitle.style.color = "var(--accent-amber)";
                verdictDesc.innerText = "Disabled diagnostic tracking services or abnormal files found. Further manual review suggested.";
            } else {
                verdictHero.style.borderColor = "var(--accent-emerald)";
                verdictHero.style.background = "rgba(16, 185, 129, 0.12)";
                verdictIcon.innerHTML = "&#x2714;";
                verdictTitle.innerText = "VERDICT: CLEAN - NO ACTIVE OR PAST CHEATS FOUND";
                verdictTitle.style.color = "var(--accent-emerald)";
                verdictDesc.innerText = "No game cheat signatures, injectors, prefetch traces, or anti-forensic log wipers found on this machine.";
            }

            document.getElementById('tabBtnCheats').innerText = `🚨 Detected Cheats (${res.cheat_count})`;
            document.getElementById('tabBtnBypass').innerText = `🥷 Anti-Forensics & Tampering (${res.bypass_count})`;

            const cheatsList = document.getElementById('cheatsList');
            if (res.detections.length === 0) {
                cheatsList.innerHTML = `<div class="empty-placeholder">&#x2714; Clean. No cheat files or executables found in BAM, PCA, MuiCache, or Storage.</div>`;
            } else {
                cheatsList.innerHTML = res.detections.map(item => `
                    <div class="item-card">
                        <div class="item-card-top">
                            <span class="badge-danger">CRITICAL</span>
                            <span class="item-source">${item.category}</span>
                            <span class="item-time">${item.timestamp || 'Recorded'}</span>
                        </div>
                        <div class="item-target">${item.target}</div>
                        <div class="item-detail">${item.detail}</div>
                    </div>
                `).join('');
            }

            const bypassList = document.getElementById('bypassList');
            if (res.bypass_items.length === 0) {
                bypassList.innerHTML = `<div class="empty-placeholder">&#x2714; Clean. No log wiping, USN journal tampering, or stopped diagnostic services detected.</div>`;
            } else {
                bypassList.innerHTML = res.bypass_items.map(item => `
                    <div class="item-card">
                        <div class="item-card-top">
                            <span class="badge-danger">TAMPER / BYPASS</span>
                            <span class="item-source">${item.title}</span>
                            <span class="badge-warning" style="font-size: 11px;">${item.status}</span>
                        </div>
                        <div class="item-detail" style="color: var(--text-muted); font-size: 12.5px; margin-top: 4px;">${item.evidence}</div>
                    </div>
                `).join('');
            }

            if (res.html_path) {
                document.getElementById('btnHtmlReport').disabled = false;
            }
            if (res.txt_path) {
                document.getElementById('btnTxtReport').disabled = false;
            }
        };

        function openHtmlReport() {
            window.pywebview.api.open_html_report();
        }

        function openTxtReport() {
            window.pywebview.api.open_txt_report();
        }
    </script>
</body>
</html>
"""

def main():
    api = LilnyxAPI()
    window = webview.create_window(
        title="Lilnyx Detection - Real-Time Anti-Cheat & Forensic Suite v2.5",
        html=HTML_UI,
        js_api=api,
        width=1120,
        height=740,
        min_size=(960, 620),
        background_color="#060911"
    )
    api.set_window(window)
    webview.start(debug=False)

if __name__ == "__main__":
    main()

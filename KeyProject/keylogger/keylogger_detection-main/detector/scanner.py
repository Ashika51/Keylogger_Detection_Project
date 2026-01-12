import os
import psutil
import subprocess
import winreg

suspicious_keywords = [
    "keylogger", "stealer", "keycaptor", "keytrace", "inputlogger",
    "keyboardhook", "refog", "monitor", "logger", "tracker"
]

whitelist_processes = {
    "systemd", "bash", "gnome-shell", "Xorg", "pulseaudio", "python3", "python",
    "chrome", "firefox", "explorer.exe", "svchost.exe", "conhost.exe", "init",
    "kworker", "systemd-journald", "dbus-daemon", "NetworkManager", "lightdm", "xfce4-session"
}

def run_full_scan():
    logs = []

    # 1. Check Refog folders
    logs.append("[1] Checking for unknown keylogger folders...")
    paths = [
        r"C:\\Program Files\\REFOG",
        r"C:\\ProgramData\\REFOG",
        os.path.expandvars(r"%APPDATA%\\REFOG")
    ]
    found = False
    for path in paths:
        if os.path.exists(path):
            logs.append(f"[!] Suspicious folder found: {path}")
            found = True
    if not found:
        logs.append("[+] No Keylogger folders found.")

    # 2. Check startup registry
    logs.append("\n[2] Scanning startup registry keys...")
    registry_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    ]
    found = False
    for root, path in registry_paths:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    if "refog" in value.lower() or "monitor" in value.lower():
                        logs.append(f"[!] Suspicious registry: {name} -> {value}")
                        found = True
        except Exception:
            continue
    if not found:
        logs.append("[+] No suspicious startup registry entries found.")

    # 3. Scan processes
    logs.append("\n[3] Scanning processes...")
    found = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = proc.info['name'].lower()
            cmdline_list = proc.info.get('cmdline')
            cmdline = ' '.join(cmdline_list).lower() if isinstance(cmdline_list, list) else ''
            if name in whitelist_processes:
                continue
            if any(key in name or key in cmdline for key in suspicious_keywords):
                logs.append(f"[!] Suspicious process: {name} (PID: {proc.pid})")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not found:
        logs.append("[+] No suspicious processes found.")

    # 4. Windows services
    logs.append("\n[4] Checking Windows services...")
    try:
        output = subprocess.check_output('sc query', shell=True, text=True)
        if "refog" in output.lower() or "monitor" in output.lower():
            logs.append("[!] Suspicious service name detected.")
        else:
            logs.append("[+] No suspicious service names detected.")
    except Exception as e:
        logs.append(f"[!] Failed to check services: {e}")

    # 5. Network connections
    logs.append("\n[5] Checking network connections...")
    suspicious_ports = [25, 587, 465, 21, 443]
    found = False
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "ESTABLISHED" and conn.raddr:
            ip, port = conn.raddr
            if port in suspicious_ports and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    logs.append(f"[!] Active connection: {proc.name()} -> {ip}:{port}")
                    found = True
                except:
                    continue
    if not found:
        logs.append("[+] No suspicious connections found.")

    logs.append("\n[✓] Full scan complete.")
    return logs

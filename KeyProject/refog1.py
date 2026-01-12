
#!/usr/bin/env python3
import os
import psutil
import socket
import winreg
import subprocess
import logging
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk
import requests
import time
import threading
import hashlib
import json
from datetime import datetime

VIRUSTOTAL_API_KEY = '6b84ce7586bd52c7f9a8ceb4905425d590a7c7598064acccfafa7aee6a94d5d1'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'
UPDATE_REPO = 'https://api.github.com/repos/CYBEREYE-001/KEYLOGGER-Detector/releases/latest'
LOG_FILE = 'suspicious_processes.log'
EXPORT_FILE = 'exported_results.txt'
VERSION = 'v2.0'

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

suspicious_keywords = [
    "keylogger", "stealer", "keycaptor", "keytrace", "inputlogger", "keyboardhook", "refog", "monitor", "logger", "tracker"
]

whitelist_processes = set([
    "systemd", "bash", "gnome-shell", "Xorg", "pulseaudio", "python3", "python", "chrome",
    "firefox", "explorer.exe", "svchost.exe", "conhost.exe", "init", "kworker", "systemd-journald",
    "dbus-daemon", "NetworkManager", "lightdm", "xfce4-session"
])

class KeyloggerDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Refog & Keylogger Detector GUI")
        self.root.geometry("880x780")
        self.root.configure(bg="#f0f0f0")
        self.scheduled_scan = False
        self.setup_ui()
        self.monitor_thread = threading.Thread(target=self.real_time_monitoring, daemon=True)
        self.monitor_thread.start()

    def setup_ui(self):
        tk.Label(self.root, text="REFoG & SYSTEM DEFENSE TOOL", font=("Arial", 16, 'bold'), bg="#f0f0f0").pack(pady=10)

        scan_frame = tk.Frame(self.root, bg="#f0f0f0")
        scan_frame.pack(pady=10)
        tk.Button(scan_frame, text="RUN FULL SCAN", command=self.full_scan, font=("Arial", 12), bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(scan_frame, text="EXIT", command=self.close_tool, font=("Arial", 12), bg="#F44336", fg="white").pack(side=tk.RIGHT, padx=5)

        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=700, mode="determinate")
        self.progress.pack(pady=10)

        self.result_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=110, height=30, font=("Courier", 10))
        self.result_area.pack(pady=10)

    def full_scan(self):
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, "[+] Starting full scan for Refog & Keyloggers...\n")
        self.progress.start()

        self.check_refog_files()
        self.check_startup_registry()
        self.check_suspicious_processes()
        self.check_windows_services()
        self.check_network_connections()

        self.progress.stop()
        self.result_area.insert(tk.END, "\n[✓] Full scan complete.\n")

    def check_refog_files(self):
        self.result_area.insert(tk.END, "\n[1] Checking for unknown keylogger folders...\n")
        paths = [
            r"C:\\Program Files\\REFOG", 
            r"C:\\ProgramData\\REFOG", 
            os.path.expandvars(r"%APPDATA%\\REFOG")
        ]
        found = False
        for path in paths:
            if os.path.exists(path):
                self.result_area.insert(tk.END, f"[!] Suspicious folder found: {path}\n")
                found = True
        if not found:
            self.result_area.insert(tk.END, "[+]  Refog Keylogger folders found.\n")

    def check_startup_registry(self):
        self.result_area.insert(tk.END, "\n[2] Scanning startup registry keys...\n")
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
                            self.result_area.insert(tk.END, f"[!] Suspicious registry: {name} -> {value}\n")
                            found = True
            except Exception:
                continue
        if not found:
            self.result_area.insert(tk.END, "[+] No suspicious startup registry entries found.\n")

    def check_suspicious_processes(self):
        self.result_area.insert(tk.END, "\n[3] Scanning processes...\n")
        found = False
        all_pids = psutil.pids()
        for count, proc in enumerate(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']), 1):
            try:
                name = proc.info['name'].lower()
                cmdline_list = proc.info.get('cmdline')
                cmdline = ' '.join(cmdline_list).lower() if isinstance(cmdline_list, list) else ''
                if name in whitelist_processes:
                    continue
                if any(key in name or key in cmdline for key in suspicious_keywords):
                    found = True
                    msg = f"[!] Suspicious: {name} (PID: {proc.pid})\n"
                    self.result_area.insert(tk.END, msg)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            self.progress['value'] = (count / len(all_pids)) * 100
            self.root.update_idletasks()
        if not found:
            self.result_area.insert(tk.END, "[+] No suspicious processes found.\n")

    def check_windows_services(self):
        self.result_area.insert(tk.END, "\n[4] Checking Windows services...\n")
        try:
            output = subprocess.check_output('sc query', shell=True, text=True)
            if "refog" in output.lower() or "monitor" in output.lower():
                self.result_area.insert(tk.END, "[!] Suspicious service name detected.\n")
            else:
                self.result_area.insert(tk.END, "[+]Refog - suspicious service names detected.\n")
        except Exception as e:
            self.result_area.insert(tk.END, f"[!] Failed to check services: {e}\n")

    def check_network_connections(self):
        self.result_area.insert(tk.END, "\n[5] Checking network connections...\n")
        suspicious_ports = [25, 587, 465, 21, 443]
        found = False
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                ip, port = conn.raddr
                if port in suspicious_ports and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        self.result_area.insert(tk.END, f"[!] Active connection: {proc.name()} -> {ip}:{port}\n")
                        found = True
                    except:
                        continue
        if not found:
            self.result_area.insert(tk.END, "[+] No suspicious connections found.\n")

    def real_time_monitoring(self):
        while True:
            if self.scheduled_scan:
                self.full_scan()
            time.sleep(30)

    def close_tool(self):
        self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = KeyloggerDetectorApp(root)
    root.mainloop()

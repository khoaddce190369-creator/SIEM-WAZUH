#!/usr/bin/env python3
# ============================================================
# FILE: custom-quarantine.py (Multi-OS Version)
# CHỨC NĂNG: Cách ly mạng Endpoint (Windows & Linux), chừa đường nối đến Wazuh Manager.
# ============================================================

import sys
import json
import subprocess
import platform

# ⚠️ QUAN TRỌNG: Thay IP này bằng IP thực tế của Wazuh Manager
WAZUH_MANAGER_IP = "192.168.0.11" 

# Nhận diện hệ điều hành để thiết lập đường dẫn ghi log
OS_TYPE = platform.system()
if OS_TYPE == "Windows":
    LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

def write_log(message):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(message + "\n")
    except Exception:
        pass

# ---------------------------------------------------------
# HÀM DÀNH CHO LINUX (IPTABLES)
# ---------------------------------------------------------
def quarantine_linux():
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "INPUT", "-s", WAZUH_MANAGER_IP, "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", WAZUH_MANAGER_IP, "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
        return True
    except Exception as e:
        write_log(f"custom-quarantine: Lỗi Linux iptables - {e}")
        return False

def unquarantine_linux():
    try:
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-F"], check=True)
        return True
    except Exception as e:
        write_log(f"custom-quarantine: Lỗi gỡ Linux iptables - {e}")
        return False

# ---------------------------------------------------------
# HÀM DÀNH CHO WINDOWS (NETSH ADVFIREWALL)
# ---------------------------------------------------------
def quarantine_windows():
    try:
        # Cho phép in/out tới Manager
        subprocess.run(f'netsh advfirewall firewall add rule name="Wazuh_Allow_In" dir=in action=allow remoteip={WAZUH_MANAGER_IP}', shell=True, check=True)
        subprocess.run(f'netsh advfirewall firewall add rule name="Wazuh_Allow_Out" dir=out action=allow remoteip={WAZUH_MANAGER_IP}', shell=True, check=True)
        # Chuyển policy mặc định thành Block toàn bộ
        subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockin,blockout', shell=True, check=True)
        return True
    except Exception as e:
        write_log(f"custom-quarantine: Lỗi Windows netsh - {e}")
        return False

def unquarantine_windows():
    try:
        # Xóa rule cho phép Manager
        subprocess.run('netsh advfirewall firewall delete rule name="Wazuh_Allow_In"', shell=True)
        subprocess.run('netsh advfirewall firewall delete rule name="Wazuh_Allow_Out"', shell=True)
        # Khôi phục policy mặc định (Thường là Block In, Allow Out)
        subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockin,allowout', shell=True, check=True)
        return True
    except Exception as e:
        write_log(f"custom-quarantine: Lỗi gỡ Windows netsh - {e}")
        return False

# ---------------------------------------------------------
# MAIN LOGIC ĐIỀU HƯỚNG
# ---------------------------------------------------------
def main():
    input_data = sys.stdin.readline()
    if not input_data:
        sys.exit(1)

    try:
        alert = json.loads(input_data)
        command = alert.get("command")
        agent_id = alert.get("parameters", {}).get("alert", {}).get("agent", {}).get("id")

        if command == "add":
            success = quarantine_windows() if OS_TYPE == "Windows" else quarantine_linux()
            if success:
                write_log(f"custom-quarantine: [ADD] Đã CÁCH LY THÀNH CÔNG Agent ID {agent_id} trên hệ điều hành {OS_TYPE}.")
        
        elif command == "delete":
            success = unquarantine_windows() if OS_TYPE == "Windows" else unquarantine_linux()
            if success:
                write_log(f"custom-quarantine: [DELETE] Đã GỠ CÁCH LY cho Agent ID {agent_id} trên hệ điều hành {OS_TYPE}.")

    except Exception as e:
        write_log(f"custom-quarantine: Lỗi - {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

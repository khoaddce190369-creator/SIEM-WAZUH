#!/usr/bin/env python3
import sys
import json
import requests

def main():
    # 1. Đọc tham số từ Wazuh truyền xuống
    alert_file_path = sys.argv[1]
    api_key = sys.argv[2]
    hook_url = sys.argv[3] # https://api.abuseipdb.com/api/v2/check

    # 2. Đọc nội dung alert
    with open(alert_file_path) as f:
        alert = json.load(f)

    # 3. Lấy IP của kẻ tấn công
    srcip = alert.get("data", {}).get("srcip") or alert.get("srcip")
    if not srcip:
        return

    # 4. Gọi API AbuseIPDB
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': srcip, 'maxAgeInDays': '90'}
    
    try:
        response = requests.get(hook_url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)

            # 5. Nếu IP có độ tin cậy độc hại (ví dụ trên 0 để test luôn)
            if score >= 0:
                # Ghi log nhãn dán vào file mà Manager đang theo dõi
                log_output = {
                    "integration": "abuseipdb",
                    "ip": srcip,
                    "score": score,
                    "country": data.get('countryCode'),
                    "description": "Phat hien IP doc hai tu AbuseIPDB"
                }
                # Ghi đè vào file active-responses.log để Rule 100099 bắt được
                with open("/var/ossec/logs/active-responses.log", "a") as ar_log:
                    ar_log.write(json.dumps(log_output) + "\n")
    except Exception:
        pass

if __name__ == "__main__":
    main()

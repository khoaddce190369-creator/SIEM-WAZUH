import requests
import json
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import Prompt cua Khoa
from prompt_playbook import build_dynamic_playbook_prompt

# ==========================================
# 1. CAU HINH HE THONG (SYSTEM CONFIG)
# ==========================================
OLLAMA_URL = "http://192.168.0.114:11434/api/generate"
OLLAMA_MODEL = "llama3.1"

# API Wazuh Manager (Active Response)
WAZUH_API_IP = "127.0.0.1"
WAZUH_API_PORT = 55000
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "hvt58v3tlrCXI2?6wCaScCwSb*OzGUbr"

# API OpenSearch (Lay Log Thuc Te)
INDEXER_IP = "192.168.0.10"
INDEXER_USER = "admin"
INDEXER_PASS = "Wazuh-Admin123."

# ---------------------------------------------
# 🔥 CẤU HÌNH TELEGRAM (DÀNH CHO CHATOPS SOAR)
# ---------------------------------------------
TELEGRAM_BOT_TOKEN = "8120297484:AAHrRZ6HXMQxGrHCqiufUpmVGBbE0l5N9JA"
CHAT_ID = "-1003916483167" 

# ==========================================
# 2. HAM THU THAP DATA THUC TE
# ==========================================
def get_latest_real_alert():
    """Lay Alert nguy hiem moi nhat tu OpenSearch"""
    print("[*] Dang ket noi OpenSearch de lay Alert thuc te...")
    url = f"https://{INDEXER_IP}:9200/wazuh-alerts-*/_search"
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": 7}}} # Chi lay alert tu level 5 tro len
                ]
            }
        },
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    try:
        resp = requests.post(url, auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=False, timeout=5)
        if resp.status_code == 200:
            hits = resp.json().get('hits', {}).get('hits', [])
            if hits:
                return hits[0]['_source']
    except Exception as e:
        print(f"[!] Loi ket noi OpenSearch 9200: {e}")
    return None

def extract_target_ip(alert_json):
    """Tu dong tim IP cua Hacker trong log"""
    data = alert_json.get("data", {})
    if "srcip" in data: return data["srcip"]
    if "source_ip" in data: return data["source_ip"]
    return None

# ==========================================
# 3. PHAN LOAI PLAYBOOK 
# ==========================================
PLAYBOOK_TYPE_RULES = {
    "BRUTE_FORCE": {
        "rule_ids": ["100512", "5710", "5711", "5712", "5720", "5721", "2502", "2503"],
        "rule_groups_any": ["authentication_failed", "brute_force", "local_brute_force", "sshd", "pam"],
        "description_keywords": ["brute force", "multiple authentication failures"]
    },
    "MALWARE_RANSOMWARE": {
        "rule_ids": ["100500", "83510", "83511", "100100"],
        "rule_groups_any": ["sysmon_event1", "malware", "virus", "ransomware", "powershell"],
        "description_keywords": ["malware", "ransomware", "suspicious process", "powershell"]
    }
}

def classify_playbook_type(alert_json: dict) -> str:
    rule_id = str(alert_json.get("rule", {}).get("id", ""))
    rule_groups = [str(g).lower() for g in alert_json.get("rule", {}).get("groups", [])]
    desc = str(alert_json.get("rule", {}).get("description", "")).lower()

    for pb_type, criteria in PLAYBOOK_TYPE_RULES.items():
        if any(rule_id.startswith(p) for p in criteria.get("rule_ids", [])): return pb_type
        if any(g in criteria.get("rule_groups_any", []) for g in rule_groups): return pb_type
        if any(k in desc for k in criteria.get("description_keywords", [])): return pb_type
    return "GENERIC_INVESTIGATION"

# ==========================================
# 4. LUONG THUC THI CHINH (MAIN EXECUTION)
# ==========================================
def run_dynamic_playbook():
    print("============================================================")
    print(" TN4 - DYNAMIC PLAYBOOK: SENT TO TELEGRAM CHATOPS")
    print("============================================================")
    
    # 1. LAY DATA THAT
    real_alert = get_latest_real_alert()
    if not real_alert:
        print("[-] Khong tim thay Alert nao moi tu OpenSearch. Ket thuc.")
        return

    rule_id = real_alert.get("rule", {}).get("id", "Unknown")
    desc = real_alert.get("rule", {}).get("description", "No description")
    print(f"[+] Phat hien Alert moi: Rule {rule_id} - {desc}")
    
    # 2. PHAN LOAI
    pb_type = classify_playbook_type(real_alert)
    print(f"[*] Python da phan loai su co: {pb_type}")
    
    # 3. GỌI AI
    print("[*] Dang gui Data cho Llama 3.1 thiet ke Playbook (Cho 20-40s)...")
    ai_prompt = build_dynamic_playbook_prompt(
        playbook_type=pb_type,
        alert=real_alert,
        tn1_enrichment={"summary": f"Canh bao moi nhat: {desc}"},
        tn2_threat_intel=None,
        event_chain=[] 
    )
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": ai_prompt,
        "system": "You are a strict SOC Automation AI. Output strictly valid JSON matching the schema.",
        "stream": False,
        "format": "json"
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        ai_json = json.loads(response.json().get("response", "{}"))
        
        ai_json_lower = {k.lower(): v for k, v in ai_json.items()}
        
        # Fallback neu AI ngop luat
        if not ai_json_lower.get("investigation_steps") and not ai_json_lower.get("action_plan"):
            print(" | - [*] AI tra ve rong. Python dang kich hoat Fallback Playbook tu Data dau vao...")
            ai_json = {
                "investigation_steps": [
                    f"Kiem tra source IP trong log de xem tan suat tan cong.",
                    f"Truy van OpenSearch rule.id: {rule_id} de tim cac su kien lien quan."
                ],
                "action_plan": {
                    "action_type": "block_ip",
                    "module": "firewall-drop",
                    "target_ip": extract_target_ip(real_alert),
                    "timeout": 3600
                }
            }
            
        # ==========================================
        # BƯỚC 4: ĐẨY BÁO CÁO LÊN TELEGRAM KÈM NÚT BẤM
        # ==========================================
        action = ai_json.get("action_plan", {})
        is_block = action.get("action_type") == "block_ip" or action.get("action") == "block_ip" or action.get("module") == "firewall-drop"
        
        if action and is_block:
            target_ip = action.get('target_ip') or extract_target_ip(real_alert)
            agent_id = real_alert.get("agent", {}).get("id", "000")
            
            if not target_ip:
                print("\n[!] Khong the trich xuat IP muc tieu tu log de chan.")
                return

            print(f"\n[*] Dang tao ban tin SOAR cho IP {target_ip}...")
            
            # Khởi tạo nội dung tin nhắn Telegram
            telegram_msg = f" *[PLAYBOOK ĐỀ XUẤT] PHÁT HIỆN TẤN CÔNG NGUY HIỂM*\n\n"
            telegram_msg += f"**Sự cố:** {desc}\n"
            telegram_msg += f"**Rule ID:** {rule_id}\n"
            telegram_msg += f"**IP Tấn công:** `{target_ip}`\n"
            telegram_msg += f"**Máy bị nhắm tới:** Agent {agent_id}\n\n"
            
            telegram_msg += f" *KẾ HOẠCH ĐIỀU TRA (MANUAL):*\n"
            for step in ai_json.get("investigation_steps", []):
                telegram_msg += f"  - {step}\n"
                
            telegram_msg += f"\n *KẾ HOẠCH ỨNG PHÓ (SOAR):*\n"
            telegram_msg += f"- Kích hoạt module `{action.get('module', 'firewall-drop')}` để chặn IP trên Tường lửa nội bộ.\n\n"
            telegram_msg += f" *Vui lòng SOC Analyst duyệt lệnh bên dưới:* "

            # Tạo nút bấm Telegram (Inline Keyboard)
            # Dữ liệu Callback Data có format: action_ip_ruleid (Ví dụ: approve_203.0.113.42_100512)
            reply_markup = {
                "inline_keyboard": [
                    [
                        {"text": "✅ APPROVE (Chặn IP)", "callback_data": f"approve_{target_ip}_{rule_id}"},
                        {"text": "❌ REJECT (Bỏ qua)", "callback_data": f"reject_{target_ip}_{rule_id}"}
                    ]
                ]
            }
            
            # Gọi API bắn tin nhắn sang Telegram
            print("[*] Ban thong bao sang Telegram...")
            resp = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", 
                json={"chat_id": CHAT_ID, "text": telegram_msg, "parse_mode": "Markdown", "reply_markup": reply_markup}
            )
            
            if resp.status_code == 200:
                print("Đã ủy quyền quyết định cho SOC Analyst trên Telegram. Script hoàn tất nhiệm vụ.")
            else:
                print(f"[-] Lỗi gửi tin Telegram: {resp.text}")
                
            # Thoát hẳn chương trình (không xài input nữa)
            sys.exit(0)

        else:
            print("\nHe thong danh gia an toan, khong can kich hoat lenh chan tu dong.")
            
    except Exception as e:
        print(f"[-] Loi He thong: {e}")

if __name__ == "__main__":
    run_dynamic_playbook()

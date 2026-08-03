#!/usr/bin/env python3
# ============================================================
# FILE: soar_backend
# PATCHED: Loại bỏ toàn bộ biến môi trường, sử dụng cấu hình cứng 
# (Hardcode) cho môi trường Lab. Khớp callback_data dạng 
# "approve_<incident_id>" / "reject_<incident_id>".
# ============================================================

import os
import re
import json
import html
import fcntl
import logging
import requests
import threading
from flask import Flask, request, jsonify
from requests.auth import HTTPBasicAuth
import urllib3

# Bỏ qua cảnh báo chứng chỉ SSL tự ký (Wazuh API nội bộ dùng cert tự ký)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] SOAR-Backend: %(message)s",
)

# ================= CẤU HÌNH HỆ THỐNG (HARDCODED) =================

TELEGRAM_BOT_TOKEN = "8120297484:AAHrRZ6HXMQxGrHCqiufUpmVGBbE0l5N9JA"
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

WAZUH_API_URL = "https://127.0.0.1:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "hvt58v3tlrCXI2?6wCaScCwSb*OzGUbr"

# Đã gỡ bỏ os.environ.get(). Để trống chuỗi này trong môi trường Lab 
# để bỏ qua xác thực Webhook.
TELEGRAM_WEBHOOK_SECRET = ""

REQUEST_TIMEOUT = 10
AUTO_ROLLBACK_SECONDS = 300

# Thư mục chứa file JSON của Alert
REPORTS_DIR = "/var/ossec/reports/incidents"

# Validate format incident_id
INCIDENT_ID_RE = re.compile(r"^INC-[0-9]{8}-[0-9A-Za-z]{1,20}$")

# =====================================================

def check_config():
    missing = [
        name
        for name, val in [
            ("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN),
            ("WAZUH_USER", WAZUH_USER),
            ("WAZUH_PASS", WAZUH_PASS),
        ]
        if not val
    ]
    if missing:
        logging.error(f"Thiếu cấu hình cứng: {', '.join(missing)}. Backend sẽ lỗi khi xử lý callback.")
    if not TELEGRAM_WEBHOOK_SECRET:
        logging.warning(
            "TELEGRAM_WEBHOOK_SECRET đang để trống — webhook đang KHÔNG xác thực, "
            "phù hợp cho môi trường Lab."
        )

def get_wazuh_jwt_token():
    token_url = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        response = requests.get(
            token_url, auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS), verify=False, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 200:
            return response.json()["data"]["token"]
        logging.error(f"Wazuh auth thất bại: HTTP {response.status_code} - {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi kết nối Wazuh API (auth): {e}")
    return None

def run_wazuh_active_response(target_ip):
    """Gọi Wazuh API v4.x để chặn IP qua firewall-drop (chạy trên manager, agents_list='000')."""
    token = get_wazuh_jwt_token()
    if not token:
        return False

    headers = {"Authorization": f"Bearer {token}"}
    ar_params = {"agents_list": "000"}
    ar_payload = {"command": "firewall-drop", "arguments": [target_ip]}

    try:
        ar_response = requests.put(
            f"{WAZUH_API_URL}/active-response",
            headers=headers,
            params=ar_params,
            json=ar_payload,
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        if ar_response.status_code == 200:
            logging.info(f"Đã bắn lệnh chặn IP {target_ip} thành công.")
            return True
        logging.error(f"Wazuh API từ chối lệnh chặn {target_ip}: HTTP {ar_response.status_code} - {ar_response.text[:200]}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi gửi lệnh Active Response cho {target_ip}: {e}")
    return False

def tg_request(method, payload):
    """Gọi Telegram Bot API có timeout + log lỗi, tránh Flask worker bị treo."""
    try:
        resp = requests.post(f"{TELEGRAM_API_URL}/{method}", json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logging.error(f"Telegram API {method} lỗi: HTTP {resp.status_code} - {resp.text[:200]}")
        return resp
    except requests.exceptions.RequestException as e:
        logging.error(f"Lỗi gọi Telegram API {method}: {e}")
        return None

def answer_callback(callback_id, text):
    tg_request("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})

def update_telegram_ui(chat_id, message_id, new_text):
    tg_request(
        "editMessageText",
        {"chat_id": chat_id, "message_id": message_id, "text": new_text, "parse_mode": "HTML"},
    )

def send_telegram_message(chat_id, text):
    tg_request("sendMessage", {"chat_id": chat_id, "text": text, "parse_mode": "HTML"})

def notify_auto_rollback(chat_id, message_id, ip_to_block):
    logging.warning(
        f"[CHƯA GỠ CHẶN THẬT] Hết {AUTO_ROLLBACK_SECONDS}s cho IP {ip_to_block} — "
        f"đây chỉ là thông báo nhắc, KHÔNG có API call gỡ chặn thật do giới hạn của Wazuh."
    )
    text = (
        f"⏰ <b>[NHẮC NHỞ]</b> Đã {AUTO_ROLLBACK_SECONDS}s từ lúc chặn IP <code>{html.escape(ip_to_block)}</code>.\n"
        f"Wazuh API không hỗ trợ tự gỡ chặn qua lời gọi ad-hoc — nếu cần gỡ, "
        f"vào Wazuh Dashboard hoặc chạy tay trên manager."
    )
    send_telegram_message(chat_id, text)

def load_incident_report(incident_id):
    """Đọc lại report đã được custom-telegram-patched.py enforce fail-safe sẵn."""
    if not INCIDENT_ID_RE.match(incident_id or ""):
        logging.error(f"incident_id không hợp lệ (khả năng bị giả mạo): {incident_id!r}")
        return None
    path = os.path.join(REPORTS_DIR, f"{incident_id}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Không tìm thấy report cho {incident_id} tại {path}")
    except Exception as e:
        logging.error(f"Lỗi đọc report {incident_id}: {e}")
    return None

def mark_incident_resolved(incident_id, resolution, analyst_name):
    if not INCIDENT_ID_RE.match(incident_id or ""):
        return False
    path = os.path.join(REPORTS_DIR, f"{incident_id}.json")
    lock_path = path + ".lock"
    try:
        with open(lock_path, "a+") as lockfile:
            fcntl.flock(lockfile, fcntl.LOCK_EX)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                pending = report.setdefault("pending_action", {})
                if pending.get("status") in ("resolved",):
                    return False  # đã xử lý trước đó rồi
                pending["status"] = "resolved"
                pending["resolution"] = resolution
                pending["resolved_by"] = analyst_name
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                return True
            finally:
                fcntl.flock(lockfile, fcntl.LOCK_UN)
    except Exception as e:
        logging.error(f"Không thể cập nhật trạng thái resolved cho {incident_id}: {e}")
        return True 

def handle_approve(incident_id, chat_id, message_id, callback_id, analyst_name, original_text):
    report = load_incident_report(incident_id)
    if report is None:
        answer_callback(callback_id, "Lỗi: không tìm thấy incident report, không thể xử lý!")
        return

    pending = report.get("pending_action", {})
    status = pending.get("status")

    if status == "auto_executed":
        answer_callback(callback_id, "IP này đã được hệ thống TỰ ĐỘNG chặn từ trước, không cần Approve.")
        return

    if not mark_incident_resolved(incident_id, "approved", analyst_name):
        answer_callback(callback_id, "Yêu cầu này đã được xử lý trước đó rồi (tránh double-click).")
        return

    action = pending.get("action", "monitor")
    target = pending.get("target_ip", "N/A")

    if action == "block_ip":
        success = run_wazuh_active_response(target)
        if success:
            answer_callback(callback_id, f"Đã chặn IP: {target}")
            new_text = (
                html.escape(original_text)
                + f"\n\n<b>[ĐÃ XỬ LÝ]</b> Analyst {html.escape(analyst_name)} đã phê duyệt chặn IP <code>{html.escape(target)}</code>."
            )
            update_telegram_ui(chat_id, message_id, new_text)
            timer = threading.Timer(AUTO_ROLLBACK_SECONDS, notify_auto_rollback, args=[chat_id, message_id, target])
            timer.daemon = True
            timer.start()
        else:
            answer_callback(callback_id, "Lỗi gọi Wazuh API, chặn IP KHÔNG thành công!")
    elif action == "isolate-machine":
        logging.warning(f"Approve isolate-machine cho {incident_id} nhưng chưa có logic thực thi — cần bổ sung.")
        answer_callback(callback_id, "Đã ghi nhận Approve, nhưng isolate-machine CHƯA được nối logic thực thi tự động — cần xử lý tay.")
        new_text = (
            html.escape(original_text)
            + f"\n\n<b>[CẦN XỬ LÝ TAY]</b> Analyst {html.escape(analyst_name)} đã Approve isolate-machine, "
              f"nhưng backend chưa hỗ trợ tự động — vui lòng cách ly máy thủ công."
        )
        update_telegram_ui(chat_id, message_id, new_text)
    else:
        answer_callback(callback_id, "Action là 'monitor', không cần thực thi gì thêm.")
        new_text = html.escape(original_text) + f"\n\n<b>[ĐÃ GHI NHẬN]</b> Analyst {html.escape(analyst_name)} xác nhận theo dõi."
        update_telegram_ui(chat_id, message_id, new_text)

def handle_reject(incident_id, chat_id, message_id, callback_id, analyst_name, original_text):
    report = load_incident_report(incident_id)
    status = (report or {}).get("pending_action", {}).get("status")

    mark_incident_resolved(incident_id, "acknowledged" if status == "auto_executed" else "rejected", analyst_name)

    if status == "auto_executed":
        answer_callback(callback_id, "Đã ghi nhận. IP liên quan đã được hệ thống tự động chặn từ trước.")
        note = f"\n\n<b>[ĐÃ GHI NHẬN]</b> Analyst {html.escape(analyst_name)} đã xem thông báo auto-block."
    else:
        answer_callback(callback_id, "Đã hủy bỏ cảnh báo (False Positive).")
        note = f"\n\n<b>[TỪ CHỐI]</b> Analyst {html.escape(analyst_name)} xác nhận False Positive. Đã bỏ qua."

    update_telegram_ui(chat_id, message_id, html.escape(original_text) + note)

# ================== FLASK WEBHOOK ====================
@app.route("/telegram-callback", methods=["POST"])
def handle_telegram_callback():
    try:
        # Xác thực request Webhook (Đã bỏ qua khi set biến TELEGRAM_WEBHOOK_SECRET rỗng)
        if TELEGRAM_WEBHOOK_SECRET:
            incoming_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
            if incoming_secret != TELEGRAM_WEBHOOK_SECRET:
                logging.warning("Webhook nhận request với secret_token sai hoặc thiếu — từ chối.")
                return jsonify({"status": "forbidden"}), 403

        update = request.get_json(silent=True)
        if not update or "callback_query" not in update:
            return jsonify({"status": "ignored"}), 200

        callback = update["callback_query"]
        callback_id = callback["id"]
        chat_id = callback["message"]["chat"]["id"]
        message_id = callback["message"]["message_id"]
        callback_data = callback.get("data", "")
        original_text = callback["message"].get("text", "")
        analyst_name = callback.get("from", {}).get("first_name", "Analyst")

        if callback_data.startswith("approve_"):
            incident_id = callback_data[len("approve_"):]
            handle_approve(incident_id, chat_id, message_id, callback_id, analyst_name, original_text)
        elif callback_data.startswith("reject_"):
            incident_id = callback_data[len("reject_"):]
            handle_reject(incident_id, chat_id, message_id, callback_id, analyst_name, original_text)
        else:
            logging.warning(f"callback_data không khớp format nào: {callback_data!r}")
            answer_callback(callback_id, "Không nhận diện được lệnh này.")

        return jsonify({"status": "processed"}), 200
    except Exception as e:
        logging.error(f"Lỗi xử lý Webhook: {e}")
        return jsonify({"status": "error"}), 500


if __name__ == "__main__":
    check_config()
    app.run(host="0.0.0.0", port=5000, threaded=True)

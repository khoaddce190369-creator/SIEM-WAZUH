#!/usr/bin/env python3
# ============================================================
# FILE: custom-telegram
# Cre: Khoa & Thái
# ============================================================

import sys
import os
import json
import glob
import tempfile
import requests
import logging
from opensearchpy import OpenSearch
from datetime import datetime
from jsonschema import validate, ValidationError

# ─────────────────────────────────────────────────────────────
# PHẦN 1: CẤU HÌNH HỆ THỐNG
# ─────────────────────────────────────────────────────────────
REPORTS_DIR = "/var/ossec/reports/incidents"                 
OLLAMA_URL  = "http://192.168.0.114:11434/api/generate"      
OLLAMA_MODEL = "llama3.1"                                    

logging.basicConfig(
    filename="/var/ossec/logs/ai_fallback.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# ─────────────────────────────────────────────────────────────
# PHẦN 2: TN3 - INCIDENT REPORT GENERATION (ĐÃ BỌC THÉP CHỐNG CRASH)
# ─────────────────────────────────────────────────────────────
def get_next_incident_id() -> str:
    """Tự động sinh ID sự cố. Có bọc try-except chống lỗi quyền thư mục."""
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True) 
        today   = datetime.now().strftime("%Y%m%d")
        pattern = os.path.join(REPORTS_DIR, f"INC-{today}-*.json")
        files   = glob.glob(pattern)
        max_seq = 0
        for f in files:
            try:
                seq_str = os.path.basename(f).split('-')[2].split('.')[0]
                max_seq = max(max_seq, int(seq_str))
            except (IndexError, ValueError):
                continue
        return f"INC-{today}-{max_seq + 1:04d}"
    except Exception as e:
        logging.error(f"[TN3] Cannot create Incident ID: {e}")
        # Lỗi thì xài ID rác, tuyệt đối không được dừng chương trình
        return f"INC-{datetime.now().strftime('%Y%m%d')}-ERROR"

def generate_incident_report(ai_result: dict, agent_meta: dict) -> dict:
    incident_id = get_next_incident_id()

    report_data = dict(ai_result)
    report_data["incident_id"] = incident_id
    
    if "patient_zero" not in report_data or not isinstance(report_data["patient_zero"], dict):
        report_data["patient_zero"] = {}
        
    if report_data["patient_zero"].get("hostname") in (None, "N/A", "", "<agent.name>"):
        report_data["patient_zero"]["hostname"] = agent_meta.get("name", "N/A")
        
    if report_data["patient_zero"].get("ip") in (None, "N/A", "", "<agent.ip>"):
        report_data["patient_zero"]["ip"] = agent_meta.get("ip", "N/A")

    REPORT_SCHEMA = {
        "type": "object",
        "properties": {
            "incident_id": {"type": "string"},
            "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Unknown"]},
            "patient_zero": {
                "type": "object",
                "properties": {"hostname": {"type": "string"}, "ip": {"type": "string"}},
                "required": ["hostname", "ip"],
                "additionalProperties": False
            },
            "affected_user": {"type": "string"},
            "attack_summary": {"type": "string"},
            "ioc": {
                "type": "object",
                "properties": {
                    "hash": {"type": "array", "items": {"type": "string"}},
                    "ip": {"type": "array", "items": {"type": "string"}},
                    "domain": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["hash", "ip", "domain"],
                "additionalProperties": False
            },
            "threat_verdict": {"type": "string"},
            "mitre_techniques": {"type": "array", "items": {"type": "string"}},
            "timeline": {"type": "array", "items": {"type": "string"}},
            "recommended_actions": {"type": "array", "items": {"type": "string"}}
        },
        "required": [
            "incident_id", "severity", "patient_zero", "affected_user",
            "attack_summary", "ioc", "threat_verdict", "mitre_techniques",
            "timeline", "recommended_actions"
        ],
        "additionalProperties": False
    }

    try:
        validate(instance=report_data, schema=REPORT_SCHEMA)
    except ValidationError as e:
        logging.error(f"[TN3] Schema validation failed for {incident_id}: {e.message}")

    filepath = os.path.join(REPORTS_DIR, f"{incident_id}.json")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"File write error: {e}")

    return report_data

_os_client = None

def get_opensearch_client() -> OpenSearch:
    global _os_client
    if _os_client is None:
        _os_client = OpenSearch(
            hosts=[{"host": "localhost", "port": 9200}],
            http_auth=("admin", "Wazuh-Admin123."),
            use_ssl=True,
            verify_certs=False, 
            ssl_show_warn=False,
        )
    return _os_client

_SOURCE_FIELDS = [
    "@timestamp", "data.win.system.eventID", "data.win.eventdata.image",
    "data.win.eventdata.commandLine", "data.win.eventdata.parentImage",
    "data.win.eventdata.processGuid", "data.win.eventdata.parentProcessGuid",
    "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort",
    "data.win.eventdata.targetFilename", "data.win.eventdata.targetObject",
    "data.win.eventdata.sourceImage", "data.win.eventdata.targetImage",
    "rule.description", "rule.groups", "full_log",
    "data.srcip", "data.srcport", "data.dstuser", "data.audit.acct",
    "data.audit.exe", "data.audit.command", "data.command",
    "data.audit.file.name", "data.audit.res", "data.tty", "data.audit.pid",
    "agent.name", "agent.ip", "rule.level",
]

def get_event_chain(identifier_value: str, os_type: str, time_window_hours: int = 48) -> list:
    if not identifier_value or str(identifier_value) == "N/A": return []
    client = get_opensearch_client()
    must = [{"range": {"@timestamp": {"gte": f"now-{time_window_hours}h", "lte": "now"}}}]
    if os_type == "windows":
        must.extend([
            {"term": {"data.win.system.providerName.keyword": "Microsoft-Windows-Sysmon"}},
            {"term": {"data.win.eventdata.processGuid.keyword": str(identifier_value)}},
            {"terms": {"data.win.system.eventID": [1, 3, 8, 10, 11, 13, 22]}}, 
        ])
    elif os_type == "linux":
        must.append({
            "bool": {
                "should": [
                    {"term": {"data.audit.pid": str(identifier_value)}},
                    {"term": {"data.pid": str(identifier_value)}},
                ],
                "minimum_should_match": 1,
            }
        })
    try:
        resp = client.search(index="wazuh-alerts-*", body={"query": {"bool": {"must": must}}, "sort": [{"@timestamp": "asc"}], "_source": _SOURCE_FIELDS, "size": 100})
        return [h["_source"] for h in resp["hits"]["hits"]]
    except Exception: return []

def get_process_tree(initial_guid: str, time_window_hours: int = 48, max_depth: int = 20) -> list:
    if not initial_guid or str(initial_guid) == "N/A": return []
    client = get_opensearch_client()
    all_events, processed, current_guids = [], set(), {str(initial_guid)}
    depth = 0
    while current_guids and depth < max_depth:
        depth += 1
        next_guids = set()
        for guid in current_guids:
            if guid in processed: continue
            processed.add(guid)
            must = [
                {"range": {"@timestamp": {"gte": f"now-{time_window_hours}h", "lte": "now"}}},
                {"term": {"data.win.system.providerName.keyword": "Microsoft-Windows-Sysmon"}},
                {"term": {"data.win.eventdata.processGuid.keyword": guid}},
                {"terms": {"data.win.system.eventID": [1, 3, 8, 10, 11, 13, 22]}},
            ]
            try:
                resp = client.search(index="wazuh-alerts-*", body={"query": {"bool": {"must": must}}, "sort": [{"@timestamp": "asc"}], "_source": _SOURCE_FIELDS, "size": 100})
                events = [h["_source"] for h in resp["hits"]["hits"]]
                all_events.extend(events)
                for e in events:
                    pg = e.get("data", {}).get("win", {}).get("eventdata", {}).get("parentProcessGuid")
                    if pg and str(pg) != "N/A" and pg not in processed: next_guids.add(str(pg))
            except Exception: pass
        current_guids = next_guids
    return all_events

def get_process_children(initial_guid: str, time_window_hours: int = 48, max_depth: int = 20) -> list:
    if not initial_guid or str(initial_guid) == "N/A": return []
    client = get_opensearch_client()
    all_events, processed, current_parents = [], set(), {str(initial_guid)}
    depth = 0
    while current_parents and depth < max_depth:
        depth += 1
        next_parents = set()
        for parent_guid in current_parents:
            if parent_guid in processed: continue
            processed.add(parent_guid)
            must = [
                {"range": {"@timestamp": {"gte": f"now-{time_window_hours}h", "lte": "now"}}},
                {"term": {"data.win.system.providerName.keyword": "Microsoft-Windows-Sysmon"}},
                {"term": {"data.win.eventdata.parentProcessGuid.keyword": parent_guid}},
                {"terms": {"data.win.system.eventID": [1, 3, 8, 10, 11, 13, 22]}},
            ]
            try:
                resp = client.search(index="wazuh-alerts-*", body={"query": {"bool": {"must": must}}, "sort": [{"@timestamp": "asc"}], "_source": _SOURCE_FIELDS, "size": 100})
                events = [h["_source"] for h in resp["hits"]["hits"]]
                all_events.extend(events)
                for e in events:
                    cg = e.get("data", {}).get("win", {}).get("eventdata", {}).get("processGuid")
                    if cg and str(cg) != "N/A" and cg not in processed: next_parents.add(str(cg))
            except Exception: pass
        current_parents = next_parents
    return all_events

def get_full_process_tree(initial_guid: str, time_window_hours: int = 48) -> list:
    if not initial_guid or str(initial_guid) == "N/A": return []
    all_events = get_process_tree(initial_guid, time_window_hours) + get_event_chain(initial_guid, os_type="windows", time_window_hours=time_window_hours) + get_process_children(initial_guid, time_window_hours)
    seen, unique = set(), []
    for e in all_events:
        key = (e.get("@timestamp"), e.get("data", {}).get("win", {}).get("eventdata", {}).get("processGuid"))
        if key not in seen:
            seen.add(key)
            unique.append(e)
    try: unique.sort(key=lambda x: x.get("@timestamp", ""))
    except Exception: pass
    return unique

SYSTEM_PROMPT = """
You are a SOC L2 Analyst specializing in Multi-OS endpoint threat detection.

TASK: Analyze a sequence of events and produce a structured threat assessment.

THREAT INTELLIGENCE INPUT
From VirusTotal:
  - Malware family  : data.attributes.meaningful_name
  - Attack type     : infer from family name (botnet, backdoor, ransomware, trojan)
From AbuseIPDB:
  - Attack type     : from data.usageType ("Data Center" -> botnet, "ISP" -> proxy)
  - Recommended action: >= 85 -> "Block IP immediately", 50-84 -> "Monitor"

THREAT INTEL VERDICT GENERATION RULE
Generate EXACTLY ONE sentence using this template if intel exists:
  "[IP/Hash] là [malware family/loại mối đe dọa], xuất phát từ [location], liên quan [attack type] — [hành động khuyến nghị]."

OUTPUT FORMAT
Return ONLY a single valid JSON object. No markdown. No text before or after JSON.
You MUST follow this exact JSON schema with 10 root fields:
{
  "incident_id": "PENDING",
  "severity": "Critical|High|Medium|Low|Unknown",
  "patient_zero": {
    "hostname": "<agent.name>",
    "ip": "<agent.ip>"
  },
  "affected_user": "<data.dstuser or data.win.eventdata.user or N/A>",
  "attack_summary": "<2-3 sentences summarizing the attack chain using specific paths/IPs>",
  "ioc": {
    "hash": ["<extracted hashes, or empty array if none>"],
    "ip": ["<extracted attacker IPs, or empty array if none>"],
    "domain": ["<extracted domains, or empty array if none>"]
  },
  "threat_verdict": "<Threat Intel verdict sentence, or 'Không có dữ liệu threat intelligence.' if no intel>",
  "mitre_techniques": ["T1059", "T1078"],
  "timeline": [
    "<[Time] - [Process/Action]>",
    "<[Time] - [Process/Action]>"
  ],
  "recommended_actions": [
    "<Action 1 naming specific IP/Process>",
    "<Action 2>"
  ]
}

CONSTRAINTS — FOLLOW STRICTLY:
1. "attack_summary" MUST reference ACTUAL field values.
2. MISSING DATA RULES (CRITICAL): 
   - NEVER output `null` values in the JSON.
   - If a string field (affected_user, threat_verdict, severity) lacks data, set it to "N/A".
   - If an array field (ioc.hash, ioc.ip, ioc.domain, mitre_techniques, timeline) lacks data, set it to an empty array [].
3. Ignore MITRE metadata from alert JSON. Prioritize behavioral analysis.
"""

def build_enrichment_prompt(events: list, threat_intel: dict = None) -> str:
    clean_events = []
    for e in events:
        e_copy = dict(e)
        if "rule" in e_copy and "mitre" in e_copy.get("rule", {}):
            e_copy["rule"] = {k: v for k, v in e_copy["rule"].items() if k != "mitre"}
        clean_events.append(e_copy)
    events_json = json.dumps(clean_events, indent=2, default=str)
    if threat_intel and any(v for v in threat_intel.values() if v is not None and v != {}):
        intel_json = json.dumps(threat_intel, indent=2, default=str)
        intel_section = f"\nThreat Intelligence:\n{intel_json}\n"
    else:
        intel_section = "\nThreat Intelligence: None available.\n"
    return f"Analyze this alert/process chain:\n\nEvents:\n{events_json}\n{intel_section}\nReturn ONLY the JSON object."

_FALLBACK_RESPONSE = {
    "incident_id":          "PENDING",
    "severity":             "High",
    "patient_zero":         {"hostname": "N/A", "ip": "N/A"},
    "affected_user":        "N/A",
    "attack_summary":       "AI Unavailable — manual review required. Please check raw logs.",
    "ioc":                  {"hash": [], "ip": [], "domain": []},
    "threat_verdict":       "Không có dữ liệu threat intelligence.",
    "mitre_techniques":     [],
    "timeline":             [],
    "recommended_actions":  ["Manually review raw alert chain in OpenSearch immediately."]
}

def enrich_alert_with_ai(events: list, threat_intel: dict = None) -> dict:
    prompt      = build_enrichment_prompt(events, threat_intel)
    full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"
    payload     = {"model": OLLAMA_MODEL, "prompt": full_prompt, "format": "json", "stream": False}
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        ai_response = response.json()
    except Exception as e:
        logging.error(f"Ollama unavailable: {e}")
        return dict(_FALLBACK_RESPONSE)

    raw = ai_response.get("response", ai_response)
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        raw_verdict = data.get("threat_verdict", "Không có dữ liệu threat intelligence.")
        verdict_str = "\n".join(str(v) for v in raw_verdict) if isinstance(raw_verdict, list) else str(raw_verdict)
        raw_ioc = data.get("ioc", {})
        if not isinstance(raw_ioc, dict): raw_ioc = {}

        return {
            "incident_id":          "PENDING",
            "severity":             data.get("severity", "Unknown"),
            "patient_zero":         data.get("patient_zero", {"hostname": "N/A", "ip": "N/A"}),
            "affected_user":        data.get("affected_user", "N/A"),
            "attack_summary":       data.get("attack_summary", "No summary provided."),
            "ioc": {
                "hash":   raw_ioc.get("hash", []) if isinstance(raw_ioc.get("hash"), list) else [],
                "ip":     raw_ioc.get("ip", []) if isinstance(raw_ioc.get("ip"), list) else [],
                "domain": raw_ioc.get("domain", []) if isinstance(raw_ioc.get("domain"), list) else []
            },
            "threat_verdict":       verdict_str,
            "mitre_techniques":     [str(t) for t in data.get("mitre_techniques", []) if t],
            "timeline":             [str(tl) for tl in data.get("timeline", []) if tl],
            "recommended_actions":  [str(a) for a in data.get("recommended_actions", []) if a] or ["No actions."]
        }
    except Exception as e:
        logging.error(f"JSON parse error: {e} | Raw: {raw}")
        return dict(_FALLBACK_RESPONSE)

def extract_threat_intel(alert: dict) -> dict:
    data = alert.get("data", {})
    vt_raw = data.get("virustotal")
    if vt_raw and isinstance(vt_raw, dict):
        virustotal = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": int(vt_raw.get("positives", 0)),
                        "total":     int(vt_raw.get("total", 0)),
                    },
                    "meaningful_name": vt_raw.get("malware"),
                    "country": "Unknown", 
                    "as_owner": "",       
                },
                "source": vt_raw.get("source", {}),
                "permalink": vt_raw.get("permalink", ""),
            }
        }
    else: virustotal = None
    abuseipdb = data.get("abuseipdb") or None
    if not virustotal and not abuseipdb: return {}
    return {"virustotal": virustotal, "abuseipdb": abuseipdb}

# ─────────────────────────────────────────────────────────────
# PHẦN 7: HÀM MAIN (ĐÃ THÊM CƠ CHẾ BẮT LỖI CỰC MẠNH)
# ─────────────────────────────────────────────────────────────
def main():
    log_file = os.path.join(tempfile.gettempdir(), "telegram_debug.log")
    try:
        if len(sys.argv) < 4:
            raise ValueError("Usage: custom-telegram <alert_file> <ignored> <hook_url>")

        alert_file = sys.argv[1]
        hook_url   = sys.argv[3]
        chat_id    = "-1003916483167" 

        with open(alert_file) as f: alert = json.load(f)

        alert_id   = str(alert.get("rule", {}).get("id", "N/A"))
        agent_name = alert.get("agent", {}).get("name", "N/A")
        agent_ip   = alert.get("agent", {}).get("ip", "N/A")
        rule_desc  = alert.get("rule", {}).get("description", "N/A")
        rule_level = int(alert.get("rule", {}).get("level", 0))
        alert_time = alert.get("timestamp", "N/A")

        data       = alert.get("data", {})
        win_guid   = data.get("win", {}).get("eventdata", {}).get("processGuid")
        linux_pid  = data.get("audit", {}).get("pid") or data.get("pid")

        events_list = [alert]
        if win_guid and str(win_guid) != "N/A":
            tree = get_full_process_tree(str(win_guid))
            events_list = tree if tree else (get_event_chain(str(win_guid), os_type="windows") or [alert])
        elif linux_pid and str(linux_pid) != "N/A":
            chain = get_event_chain(str(linux_pid), os_type="linux", time_window_hours=2)
            if chain: events_list = chain

        threat_intel = extract_threat_intel(alert)
        ai_result    = enrich_alert_with_ai(events_list, threat_intel)

        # Mặc định report_data luôn phải có giá trị, không bao giờ được None
        report_data = generate_incident_report(ai_result, {"name": agent_name, "ip": agent_ip}) or ai_result
        inc_id = report_data.get("incident_id", "INC-ERROR")

        groups     = alert.get("rule", {}).get("groups", [])
        groups_str = " ".join(f"<code>{g}</code>" for g in groups) if groups else "N/A"

        src_ip = data.get("ip") or data.get("srcip") or alert.get("srcip") or "N/A"
        
        mitre_list = report_data.get("mitre_techniques", [])
        top_mitre  = ", ".join(f"<code>{m}</code>" for m in mitre_list[:3]) or "N/A"

        actions     = report_data.get("recommended_actions", ["Investigate manually"])
        top_actions = " | ".join(f"<code>{a}</code>" for a in actions[:3])
        
        ioc_dict = report_data.get("ioc", {})
        ioc_ips  = ", ".join(ioc_dict.get("ip", [])) or "None"
        ioc_hash = ", ".join(ioc_dict.get("hash", [])) or "None"
        
        timeline = report_data.get("timeline", [])
        timeline_str = "\n".join(f"  └ <i>{tl}</i>" for tl in timeline[-2:]) or "  └ <i>No timeline extracted</i>"

        if alert_id in ("5712", "5720", "100512"):
            header = f"<b>REMOTE BRUTE-FORCE — rule.level {rule_level}</b>\n"
        elif rule_level >= 12:   header = f"🚨 <b>CRITICAL — rule.level {rule_level}</b>\n"
        elif rule_level >= 8:  header = f"🟠 <b>HIGH — rule.level {rule_level}</b>\n"
        else:                  header = f"🟡 <b>MEDIUM — rule.level {rule_level}</b>\n"

        text  = header
        text += f"<i>{rule_desc}</i>\n"
        text += f"<b>{inc_id}</b>\n"
        text += "━━━━━━━━━━━━━━━━━━\n"

        text += "<b>[1] Block 1 — Alert info</b>\n"
        text += f"├ <b>Rule ID:</b> <code>{alert_id}</code>\n"
        text += f"├ <b>Groups:</b> {groups_str}\n"
        text += f"├ <b>Patient Zero:</b> <code>{report_data.get('patient_zero', {}).get('hostname', 'N/A')}</code>\n"
        text += f"└ <b>Time:</b> {alert_time}\n\n"

        text += "<b>[2] Block 2 — Attack Summary</b>\n"
        text += f"<i>{report_data.get('attack_summary', 'N/A')}</i>\n"
        text += f"├ <b>Severity:</b> <b>{report_data.get('severity', 'N/A')}</b>\n"
        text += f"├ <b>Affected User:</b> <code>{report_data.get('affected_user', 'N/A')}</code>\n"
        text += f"└ <b>Timeline snippet:</b>\n{timeline_str}\n\n"

        text += "<b>[3] Block 3 — Threat Verdict & IOCs</b>\n"
        text += f"├ <b>Attacker IP:</b> <code>{src_ip}</code>\n"
        text += f"├ <b>Verdict:</b> <i>{report_data.get('threat_verdict', 'N/A')}</i>\n"
        text += f"├ <b>IOC IPs:</b> <code>{ioc_ips}</code>\n"
        text += f"├ <b>IOC Hashes:</b> <code>{ioc_hash}</code>\n"
        text += f"└ <b>MITRE:</b> {top_mitre}\n\n"

        text += "<b>[4] Block 4 — Action Plan</b>\n"
        text += f"├ <b>Top actions:</b> {top_actions}\n"
        text += f"└ <b>Incident ID:</b> <code>{inc_id}</code>\n"

        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": {
                "inline_keyboard": [[
                    {"text": "✅ Approve Block IP", "callback_data": f"approve_{src_ip}_{alert_id}"},
                    {"text": "❌ Reject", "callback_data": f"reject_{alert_id}"},
                ]]
            },
        }
        requests.post(hook_url, json=payload, timeout=10)

    except Exception as e:
        # Cơ chế bắt lỗi cực mạnh, không bao giờ bị Permission Denied nữa
        try:
            with open(log_file, "a") as log:
                log.write(f"{datetime.now()} Lỗi nghiêm trọng: {e}\n")
        except Exception:
            pass

if __name__ == "__main__":
    main()

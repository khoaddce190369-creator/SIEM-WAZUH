# WAZUH SIEM — Hệ thống giám sát an ninh tích hợp AI

Hệ thống SIEM phân tán dựa trên Wazuh, tích hợp mô hình ngôn ngữ lớn (LLM) để làm giàu cảnh báo, tra cứu thông tin mối đe dọa và tự động phản ứng sự cố.

[![Wazuh](https://img.shields.io/badge/Wazuh-v4.14.5-blue?style=flat-square)](https://wazuh.com)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-orange?style=flat-square)](https://opensearch.org)
[![Python](https://img.shields.io/badge/Python-3.10+-green?style=flat-square)](https://python.org)
[![Ollama](https://img.shields.io/badge/AI-Llama_3.1_Local-purple?style=flat-square)](https://ollama.ai)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK_Mapped-red?style=flat-square)](https://attack.mitre.org)

Phase 1 — Dự án thực tập | 06/05/2026 – 03/06/2026

---

## Mục lục

- [Tổng quan dự án](#tổng-quan-dự-án)
- [Kiến trúc hệ thống](#kiến-trúc-hệ-thống)
- [IP Plan & Môi trường lab](#ip-plan--môi-trường-lab)
- [Công nghệ sử dụng](#công-nghệ-sử-dụng)
- [Mô tả các thành phần](#mô-tả-các-thành-phần)
- [Tính năng AI tích hợp](#tính-năng-ai-tích-hợp)
- [Detection Engineering](#detection-engineering)
- [Automation & Active Response](#automation--active-response)
- [Cấu trúc Repository](#cấu-trúc-repository)
- [Hướng dẫn triển khai](#hướng-dẫn-triển-khai)
- [Kết quả kiểm thử xâm nhập](#kết-quả-kiểm-thử-xâm-nhập)
- [Kết quả đạt được](#kết-quả-đạt-được)
- [Thành viên nhóm](#thành-viên-nhóm)
- [Roadmap — Phase 2](#roadmap--phase-2)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)

---

## Tổng quan dự án

Dự án này được thực hiện trong khuôn khổ kỳ thực tập OJT SU26 tại Đại học FPT, dưới sự định hướng và hỗ trợ chuyên môn của anh Phạm Ngọc Chánh(Trưởng phòng (Phòng Hạ tầng số Sở KH & CN Vĩnh Long)). Mục tiêu cốt lõi của dự án là xây dựng một hệ thống SIEM (Security Information and Event Management) toàn diện dựa trên kiến trúc phân tán Wazuh (Wazuh Distributed Architecture). Điểm nhấn kỹ thuật của hệ thống là việc tích hợp mô hình ngôn ngữ lớn triển khai cục bộ (Llama 3.1 vận hành qua Ollama), nhằm tối ưu hóa và tự động hóa quy trình phân tích cảnh báo cũng như phản ứng sự cố an toàn thông tin.

### Vấn đề thực tiễn được giải quyết

| Vấn đề | Giải pháp trong dự án | Kết quả đo được |
|---|---|---|
| Phát hiện tấn công trễ — endpoint bị xâm phạm trước khi có cảnh báo | Sysmon (Windows) + Sysmon for Linux + auditd cung cấp telemetry ở tầng kernel | Phát hiện trong vòng dưới 30 giây |
| SOC analyst bị quá tải với hàng nghìn cảnh báo mỗi ngày | AI tự động phân tích, phân loại mức độ nghiêm trọng, mapping MITRE, đề xuất hành động | Giảm ~70% thời gian triage |
| Phản ứng chậm — 10–30 phút từ phát hiện đến chặn tấn công | Active Response tự động + Telegram cảnh báo thời gian thực | Thời gian phản ứng xuống dưới 15 giây |
| Cảnh báo đơn lẻ thiếu ngữ cảnh để hiểu chuỗi tấn công | AI gom ProcessGuid/PID chain, tái tạo toàn bộ timeline tấn công | Bao phủ được nhiều kịch bản kill chain thực tế |

### Phạm vi Phase 1

| Trong phạm vi | Ngoài phạm vi |
|---|---|
| Windows 10/11 + Sysmon (kernel-level) | macOS, IoT, OT/ICS endpoints |
| Ubuntu Linux + Sysmon for Linux + auditd | Cloud network, WAN traffic |
| Gateway/Router nội bộ qua Syslog | Web app WAF, database log |
| AbuseIPDB + VirusTotal (IP/hash lookup) | Commercial TI feed, ISAC |
| Llama 3.1 Local (100% nội bộ, không rò rỉ dữ liệu) | LLM fine-tuned trên dữ liệu bảo mật |
| Telegram alert + block IP + rollback | SOAR ticketing orchestration |
| Red/Purple Team trong lab nội bộ | Pentest môi trường production |

---

## Kiến trúc hệ thống

### Sơ đồ tổng thể

```
[ NGUỒN LOG ]
      |
      +-- Windows Agent (192.168.0.171)     Sysmon + FIM + auditd              ---|
      |                                                                           |
      +-- Linux Agent (192.168.0.141)       Sysmon for Linux + FIM + auditd    ---|-- TCP 1514
      |                                                                           |
      +-- Syslog Gateway (192.168.0.100)    Router/Firewall                    ---|-- UDP 514
                                                                                  |
                                                                                  v
                                                                          [ WAZUH MANAGER ]
                                                                            192.168.0.11
                                                                            Decode -> Rule Engine
                                                                            Alert Generation
                                                                            Active Response
                                                                                 |
                                                                      Filebeat (HTTPS port 9200)
                                                                                 |
                                                                                 v
                                                                          [ WAZUH INDEXER ]
                                                                            192.168.0.10
                                                                            OpenSearch 2.x
                                                                            Lưu trữ alert theo ngày
                                                                                 |
                                                 +-------------------------------+-------------------------------+
                                                 |                               |                               |
                                                 v                               v                               v
                                      [ WAZUH DASHBOARD ]              [ AI PIPELINE ]                      [ TELEGRAM BOT ]
                                        192.168.0.12                   Llama 3.1 / Ollama                   Kênh cảnh báo thời gian thực
                                        Giao diện SOC analyst          TN1: Alert Enrichment                4-Block UI/UX
                                        Security Events                TN1+: Multi-Alert Correlation        Nút Approve/Reject    
                                        MITRE Heatmap                  TN2: TI Summarization                Lệnh /query
                                        Discover / Visualize           TN3: Incident Report            
                                        Agent Management               TN4: Dynamic Playbook
                                                                       TN5: NL-to-DSL Query
                                                                       TN6: Gap Analysis
```

### Luồng dữ liệu chi tiết

**Luồng 1 — Log đến Dashboard:**
```
Endpoint -> Wazuh Agent [TCP 1514] -> Wazuh Manager
-> Filebeat [HTTPS 9200] -> Wazuh Indexer
-> Dashboard (OpenSearch DSL query) -> SOC Analyst
```

**Luồng 2 — AI Pipeline (Alert đến Telegram):**
```
Wazuh Alert -> Python script -> Query ProcessGuid/PID chain (OpenSearch)
-> AbuseIPDB (IP reputation) + VirusTotal (file hash)
-> Llama 3.1 / Ollama (phân tích: severity + MITRE + narrative + actions)
-> Lưu Incident Report JSON tại Manager
-> Telegram 4-Block + nút Approve/Reject -> Analyst
Tổng thời gian: 10–15 giây từ khi rule match đến khi analyst nhận tin nhắn
```

**Luồng 3 — Active Response:**
```
Alert rule.level >= 12 -> Telegram thông báo analyst
-> Analyst bấm Approve HOẶC auto-mode (level >= 14 + AbuseIPDB >= 80)
-> Manager gọi PUT /active-response API
-> Agent thực thi: iptables DROP (Linux) hoặc netsh firewall (Windows)
-> Timer 300 giây -> Tự động rollback -> Thông báo Telegram
```

---

## IP Plan & Môi trường lab

| Node | Địa chỉ IP | Hệ điều hành | RAM | Vai trò |
|---|---|---|---|---|
| Wazuh Manager | 192.168.0.11 | Ubuntu Server 22.04 | 4GB | Xử lý log, rule engine, REST API |
| Wazuh Indexer | 192.168.0.10 | Ubuntu Server 22.04 | 8GB | Lưu trữ OpenSearch, query engine |
| Wazuh Dashboard | 192.168.0.12 | Ubuntu Server 22.04 | — | Giao diện web (cùng máy với Indexer) |
| Windows Victim | 192.168.0.171 | Windows 10/11 | 4GB | Endpoint + Wazuh Agent + Sysmon |
| Linux Victim | 192.168.0.141 | Ubuntu 22.04 | 2GB | Endpoint + Wazuh Agent + Sysmon for Linux + auditd |
| Kali Attacker | 192.168.0.168 | Kali Linux 2024 | 4GB | Red Team — không cài Agent |
| Gateway | 192.168.0.100 | Router/Firewall | — | Nguồn Syslog, giả lập thiết bị mạng |

Mạng LAN nội bộ với router riêng của nhóm để tránh xung đột IP. ZeroTier overlay sẵn sàng cho trường hợp các máy khác mạng.

---

## Công nghệ sử dụng

| Tầng | Công nghệ | Phiên bản | Mục đích |
|---|---|---|---|
| SIEM Core | Wazuh Manager | v4.14.5 | Nhận log, giải mã, rule engine, sinh cảnh báo |
| Lưu trữ | Wazuh Indexer (OpenSearch) | 2.x | Lưu trữ alert, DSL query, aggregation |
| Giao diện | Wazuh Dashboard | v4.7.5 | Web UI, MITRE heatmap, Discover, visualization |
| Log Shipper | Filebeat | 8.x | Pipeline Manager -> Indexer |
| Giám sát Windows | Sysmon (Sysinternals) | v15.x | Sự kiện kernel-level: process, network, file, registry |
| Giám sát Linux (1) | Sysmon for Linux | v15.x | Giám sát kernel-level tương đương Sysmon Windows |
| Giám sát Linux (2) | auditd | 3.x | Kiểm tra syscall: execve, connect, open |
| Mô hình AI | Llama 3.1 via Ollama | 8B | LLM chạy nội bộ — 100% offline, không rò rỉ dữ liệu |
| Tự động hóa | Python | 3.10+ | AI pipeline, gọi API, Telegram, Active Response |
| Threat Intel | AbuseIPDB API v2 | — | Tra cứu điểm uy tín IP |
| Threat Intel | VirusTotal API v3 | — | Tra cứu hash file, xác định dòng mã độc |
| Cảnh báo | Telegram Bot API | — | Thông báo analyst thời gian thực |
| Ngôn ngữ query | OpenSearch DSL | — | Gom chuỗi ProcessGuid/PID, threat hunting |
| Ngôn ngữ decoder | PCRE2 Regex | — | Custom decoder, trích xuất field |
| Khung phân loại | MITRE ATT&CK | Enterprise v14 | Mapping kỹ thuật tấn công vào rule |

---

## Mô tả các thành phần

### Wazuh Manager (192.168.0.11)

Trung tâm xử lý của toàn bộ hệ thống SIEM. Mọi log đều đi qua đây trước khi được lưu vào Indexer.

| Thuộc tính | Chi tiết |
|---|---|
| Phiên bản | Wazuh v4.14.5 (RC/Pre-release, có version spoofing để đồng bộ API) |
| Cổng lắng nghe | 1514/TCP+UDP (Agent), 514/UDP (Syslog), 55000/TCP (REST API) |
| Các daemon chính | ossec-remoted, ossec-analysisd, ossec-syscheckd, ossec-execd, wazuh-authd |
| File cấu hình chính | /var/ossec/etc/ossec.conf |
| Custom Decoder | /var/ossec/etc/decoders/local_decoder.xml |
| Custom Rules | /var/ossec/etc/rules/local_rules.xml |
| File alert output | /var/ossec/logs/alerts/alerts.json |
| Active Response scripts | /var/ossec/active-response/bin/ |

Luồng xử lý bên trong Manager (ossec-analysisd):
```
Bước 1: ossec-remoted nhận raw log từ Agent (TCP 1514) hoặc Syslog (UDP 514)
Bước 2: Pre-decode — tách timestamp, hostname, tên chương trình
Bước 3: Decoder chain (parent -> child) — OS_Match hoặc PCRE2 Regex trích xuất field
Bước 4: Rule Engine — so sánh field với điều kiện rule, correlation theo timeframe
Bước 5: Sinh alert JSON đầy đủ field
Bước 6: Active Response — nếu rule có tag <active-response> thì trigger script trên agent
```

### Wazuh Indexer (192.168.0.10)

Hệ thống lưu trữ và tìm kiếm, xây dựng trên nền OpenSearch.

| Thuộc tính | Chi tiết |
|---|---|
| Nền tảng | OpenSearch (fork mã nguồn mở của Elasticsearch) |
| Cổng | 9200/TCP (REST API), 9300/TCP (cluster internal) |
| Index pattern | wazuh-alerts-4.x-YYYY.MM.DD (xoay vòng theo ngày) |
| Chế độ cluster | Single-node trong lab (1 shard chính, 0 replica) |

### Wazuh Dashboard (192.168.0.12)

Giao diện web dành cho SOC analyst, xây dựng trên OpenSearch Dashboards.

| Module | Chức năng |
|---|---|
| Security Events | Xem toàn bộ alert, lọc theo mọi field, drill-down chi tiết |
| Threat Intelligence | IOC lookup, MITRE ATT&CK coverage heatmap |
| File Integrity | Sự kiện FIM: file thêm/sửa/xóa, so sánh hash |
| Agents | Danh sách agent, trạng thái, OS. Thao tác: restart, upgrade |
| Management | Xem Rule, Decoder, Cấu hình. Công cụ log test |
| Discover | Ad-hoc query bằng KQL/Lucene, duyệt raw log |
| Dev Tools | Chạy raw DSL query trực tiếp trên OpenSearch |

### Sysmon — Giám sát Windows tầng kernel (WORKSTATION-01)

Sysmon là driver Windows của Microsoft Sysinternals, hoạt động ở kernel mode, ghi nhận sự kiện hệ thống với độ chi tiết vượt xa Windows Event Log mặc định.

| Event ID | Tên sự kiện | Phát hiện gì |
|---|---|---|
| 1 | ProcessCreate | Mọi process được tạo: image, commandLine, parentImage, processGuid, hash |
| 3 | NetworkConnection | Kết nối TCP/UDP ra ngoài: destinationIp, destinationPort — phát hiện C2 callback |
| 8 | CreateRemoteThread | Tiêm code vào process khác qua API CreateRemoteThread — T1055 |
| 10 | ProcessAccess | Process đọc bộ nhớ process khác — phát hiện dump LSASS — T1003 |
| 11 | FileCreate | File mới được tạo: targetFilename — phát hiện payload drop vào Temp |
| 13 | RegistryValueSet | Ghi vào registry — phát hiện persistence qua Run key — T1547 |
| 22 | DNSEvent | DNS query — phát hiện DGA, DNS-based C2, domain fronting |

### Sysmon for Linux — Giám sát Linux tầng kernel (ubuntu-admin)

Sysmon for Linux là phiên bản Linux của Microsoft Sysinternals Sysmon, cung cấp khả năng giám sát kernel-level tương đương với Sysmon trên Windows. Chạy trên Linux Agent (ubuntu-admin, 192.168.0.141).

| Event ID | Tên sự kiện | Phát hiện gì |
|---|---|---|
| 1 | ProcessCreate | Mọi process được tạo trên Linux: image, commandLine, parentImage, processGuid |
| 3 | NetworkConnection | Kết nối ra ngoài: destinationIp, destinationPort — phát hiện C2, lateral movement |
| 5 | ProcessTerminate | Process kết thúc — theo dõi vòng đời process |
| 11 | FileCreate | File mới được tạo: targetFilename — phát hiện payload drop vào /tmp |
| 23 | FileDelete | File bị xóa — phát hiện hành vi xóa dấu vết |

Log được ghi vào /var/log/syslog hoặc journal, Wazuh Agent đọc và gửi về Manager qua TCP 1514.

### auditd — Kiểm tra syscall Linux (ubuntu-admin)

auditd là framework kiểm tra syscall ở tầng kernel, ghi nhận mọi syscall theo quy tắc được định nghĩa trong audit rules.

| Audit Rule trong lab | Syscall giám sát | Mục đích phát hiện |
|---|---|---|
| -S execve -k lab_exec | execve (thực thi process) | Mọi lệnh được thực thi trên Linux |
| -S connect -k lab_network | connect (kết nối mạng) | Kết nối ra ngoài: phát hiện C2, exfiltration |
| -S open,openat /etc/shadow -k lab_cred | mở file | Đọc /etc/shadow: phát hiện đánh cắp thông tin xác thực |

Vấn đề kỹ thuật đã phát hiện và giải quyết trong dự án:

```
Lỗi: auditd decoder không trích xuất data.audit.pid trong một số định dạng log

Triệu chứng: wazuh-logtest không thấy audit.pid trong Phase 2 output,
nhưng Dashboard thấy data.audit.pid — 1 hit với pid=15499.

Nguyên nhân: Default decoder auditd-syscall có regex lớn yêu cầu các field
a0/a1/a2/a3/items. Một số log format thiếu các field này -> decoder fail
-> fallback auditd-generic không trích xuất pid -> data.audit.pid null.

Giải pháp: Thêm custom decoder vào local_decoder.xml:

<decoder name="auditd-syscall">
  <parent>auditd</parent>
  <regex offset="after_regex"> pid=(\d+)</regex>
  <order>audit.pid</order>
</decoder>

Lưu ý: wazuh-logtest có giới hạn — không hiển thị đầy đủ output của toàn bộ
decoder chain. Field thực tế trong OpenSearch document có thể đúng dù
logtest không hiển thị.
```

### FIM — File Integrity Monitoring

Wazuh FIM (Syscheck) giám sát thay đổi file system theo thời gian thực (inotify trên Linux, USN Journal trên Windows).

```
Thư mục được giám sát:
  Linux:   /etc, /bin, /sbin, /usr/bin, /tmp (realtime)
  Windows: %WINDIR%\System32, %WINDIR%\Temp, %PROGRAMDATA%
```

| Field trong FIM Alert | Ý nghĩa |
|---|---|
| syscheck.path | Đường dẫn đầy đủ file bị thay đổi |
| syscheck.event | Loại thay đổi: added / modified / deleted |
| syscheck.sha256_before | Hash trước khi thay đổi |
| syscheck.sha256_after | Hash sau khi thay đổi — dùng để tra cứu VirusTotal |
| syscheck.mtime_after | Thời điểm sửa đổi — phát hiện timestomping nếu bất thường |

### Syslog — Giám sát thiết bị mạng

Wazuh Manager hoạt động như Syslog receiver để nhận log từ gateway, router, switch qua UDP port 514. Trong lab, gateway Linux giả lập iptables log được gửi như Syslog UDP.

### Filebeat — Chuyển tiếp alert (Manager -> Indexer)

Filebeat đọc alert JSON từ /var/ossec/logs/alerts/alerts.json và chuyển sang Indexer. Có buffer nội bộ đảm bảo không mất alert khi Indexer tạm thời ngừng hoạt động.

---

## Tính năng AI tích hợp

Dự án tích hợp AI (Ollama Local — Llama 3.1:8b) vào pipeline SIEM để tự động hóa 6 tính năng cụ thể. Triết lý thiết kế: Human-in-the-loop — AI chỉ là công cụ hỗ trợ, analyst luôn là người ra quyết định cuối cùng. AI chạy 100% nội bộ qua Ollama — không có dữ liệu log nào rời khỏi hạ tầng.

Nguyên tắc tích hợp AI:
```
1. AI làm giàu dữ liệu, không tự thực thi: AI phân tích và đề xuất, không tự động block hay xóa.
2. Dự phòng an toàn: Nếu AI service down -> pipeline vẫn chạy, Telegram gửi alert không có enrichment.
3. Ngưỡng confidence: AI trả về confidence score. Nếu < 0.5 -> action = 'Manual review only'.
4. Output format cố định: JSON schema được định nghĩa nghiêm ngặt.
5. Bảo mật dữ liệu: AI chạy local 100% — không có log nào ra ngoài internet.
```

### Luồng AI Pipeline tổng quan

```
Wazuh Alert (JSON)
        |
        v
+-------------------------------------------------------+
|                    AI PIPELINE                        |
|                                                       |
| Bước 1: Trích xuất ProcessGuid (Windows) / PID(Linux) |
|          -> OpenSearch DSL query gom chuỗi sự kiện    |
|                                                       |
| Bước 2: Làm giàu Threat Intelligence                  |
|          -> AbuseIPDB (điểm uy tín IP)                |
|          -> VirusTotal (hash file, dòng mã độc)       |
|                                                       |
| Bước 3: Phân tích AI nội bộ (Llama 3.1 / Ollama)      |
|          Đầu vào: chuỗi sự kiện JSON + dữ liệu TI     |
|          Đầu ra:  severity, MITRE, narrative, actions |
|                                                       |
| Bước 4: Sinh Incident Report                          |
|          -> /var/ossec/reports/incidents/INC-*.json   |
|                                                       |
| Bước 5: Telegram 4-Block + nút Approve/Reject         |
|          -> Analyst quyết định -> Active Response     |
+-------------------------------------------------------+
```

### TN1: AI Alert Enrichment — Làm giàu ngữ cảnh cảnh báo (HOÀN THÀNH)

Tính năng cốt lõi nhất của tích hợp AI. Khi có Wazuh alert, pipeline gom toàn bộ chuỗi sự kiện ProcessGuid (Windows) hoặc PID (Linux) của process liên quan, kết hợp dữ liệu threat intelligence, rồi gọi Llama 3.1 để phân tích.

Lý do cần ProcessGuid/PID chain thay vì xử lý từng sự kiện đơn lẻ:

```
Wazuh mặc định xử lý từng sự kiện độc lập. Một cuộc tấn công thực tế có chuỗi:
PowerShell spawn (Event 1) -> Network C2 (Event 3) -> File drop (Event 11) -> Registry persist (Event 13)

Nếu AI chỉ nhận 1 sự kiện đơn lẻ (ví dụ Event 3: kết nối mạng), AI không thể biết:
- Process nào đang kết nối (không có commandLine)
- Process đó được tạo từ đâu (không có parentImage)
- Trước đó có file drop hay ghi registry không

ProcessGuid (Windows) / PID (Linux) là ID duy nhất kết nối toàn bộ sự kiện
của một process trong suốt vòng đời của nó.
```

Correlation Query (OpenSearch DSL) — Windows:
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.system.providerName.keyword": "Microsoft-Windows-Sysmon" } },
        { "term": { "data.win.eventdata.processGuid.keyword": "{{TARGET_PROCESSGUID}}" } },
        { "terms": { "data.win.system.eventID": [1, 3, 8, 10, 11, 13, 22] } },
        { "range": { "@timestamp": { "gte": "now-2h", "lte": "now" } } }
      ]
    }
  },
  "sort": [{ "@timestamp": "asc" }],
  "size": 100
}
```

Lý do dùng "term" thay "match": ProcessGuid có dạng {A1B2C3D4-...} chứa ký tự đặc biệt. "match" tokenize chuỗi gây khớp sai. "term" so sánh exact value.

Correlation Query — Linux (theo PID):
```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "agent.name.keyword": "ubuntu-admin" } },
        { "term": { "data.audit.pid": "<PID>" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "_source": ["@timestamp","data.audit.pid","data.audit.exe","data.audit.command",
              "data.audit.key","data.audit.success","syscheck.path","rule.id","rule.level"],
  "sort": [{ "@timestamp": "asc" }],
  "size": 100
}
```

Định dạng đầu ra AI (10 trường):
```json
{
  "incident_id":         "INC-20260529-0006",
  "severity":            "High",
  "patient_zero":        "WORKSTATION-01",
  "affected_user":       "john.doe",
  "attack_summary":      "PowerShell với encoded command kết nối IP 103.148.81.119:4444, drop file svchost_fake.exe, ghi registry Run key để duy trì persistence",
  "ioc":                 { "ips": ["103.148.81.119"], "hashes": ["abc123..."] },
  "threat_verdict":      "IP bị report 847 lần trên AbuseIPDB. Hash khớp với Trojan.GenericKD",
  "mitre_techniques":    ["T1059.001", "T1547.001", "T1071.001"],
  "timeline":            "10:00:01 Process spawn -> 10:00:03 C2 connect -> 10:00:05 File drop -> 10:00:08 Registry persist",
  "recommended_actions": ["Block IP 103.148.81.119", "Cô lập WORKSTATION-01", "Kiểm tra lateral movement"]
}
```

Định dạng Telegram 4-Block:
```
HIGH — REMOTE BRUTE-FORCE
INC-20260529-0006
------------------
[1] Thông tin cảnh báo
    Rule: sshd brute force
    Patient Zero: ubuntu-admin
    Thời gian: 2026-05-29T03:37:10Z

[2] Tóm tắt tấn công
    Mức độ: High | Người dùng bị ảnh hưởng: root
    AI Narrative: "Brute force từ IP 192.168.0.168, 847 lần/60 giây..."

[3] Threat Intelligence
    IP: 192.168.0.168 — Điểm: 87/100 (AbuseIPDB)
    MITRE: T1110.001 (Password Guessing)

[4] Hành động đề xuất
    [Approve Block IP] [Reject]
```

Cơ chế dự phòng 2 lớp: Nếu AI timeout (> 10s) -> gửi alert thô 4-block kèm thông báo "AI Unavailable", ghi vào ai_fallback.log. Nếu parse JSON fail -> gửi raw alert, không crash pipeline.

### TN1 (Mở rộng): AI Multi-Alert Incident Correlation (HOÀN THÀNH)

Mở rộng của TN1: thay vì phân tích một chuỗi process, tính năng này gom tất cả alert trên một endpoint trong một khoảng thời gian và tái tạo toàn bộ attack timeline. Dùng cho điều tra sau khi đã xác nhận có tấn công.

| Đặc điểm | TN1 — Chuỗi process đơn | TN1 Mở rộng — Đa cảnh báo |
|---|---|---|
| Kích hoạt | Mỗi Wazuh alert riêng lẻ | Analyst chủ động khi cần điều tra |
| Phạm vi | Sự kiện cùng ProcessGuid/PID | Toàn bộ alert trên agent X trong khoảng thời gian Y |
| Trường hợp dùng | Triage thời gian thực | Điều tra sự cố toàn diện |
| Đầu ra AI | Severity, MITRE, narrative ngắn, actions | Narrative dài, kill chain stages, patient_zero |

### TN2: AI Threat Intel Summarization — Tóm tắt Threat Intelligence (HOÀN THÀNH)

Thay vì hiển thị raw JSON từ VirusTotal/AbuseIPDB (100+ dòng), AI tóm tắt thành 1 câu kết luận bằng ngôn ngữ tự nhiên.

```
Đầu vào (raw VT JSON):
{ "data": { "attributes": { "last_analysis_stats": { "malicious": 68, ... } } } }

Đầu ra (AI verdict):
"Hash khớp với Trojan.GenericKD.48291053, bị 68/74 engine phát hiện — xác suất độc hại rất cao."
```

Ràng buộc trong prompt: Ép AI xuất đúng 1 câu theo template, giới hạn dưới 30 từ, tuyệt đối không giải thích dài dòng. Fallback khi gặp HTTP 429 Rate Limit: trả về "Không có dữ liệu threat intelligence."

### TN3: AI Incident Report Generation — Sinh báo cáo sự cố (ĐANG PHÁT TRIỂN — Phase 2)

Thu thập toàn bộ attack narrative, threat verdict và metadata của agent để sinh ra Báo cáo sự cố hoàn chỉnh. Báo cáo được lưu dạng file JSON tại Manager và hiển thị lên Telegram.

| Thuộc tính | Chi tiết |
|---|---|
| JSON Schema | 10 trường bắt buộc: incident_id, severity, patient_zero, affected_user, attack_summary, ioc, threat_verdict, mitre_techniques, timeline, recommended_actions |
| Ràng buộc | Bắt buộc dùng "N/A" cho trường string bị thiếu, dùng mảng rỗng [] cho IOC bị thiếu — tuyệt đối không dùng null để tránh crash hệ thống |
| Kiểm tra | Dùng thư viện jsonschema của Python để validate báo cáo trước khi lưu |
| Trạng thái | ĐANG PHÁT TRIỂN — AI vẫn chưa tạo được report đúng format ổn định. Cần đổi model AI hoặc train AI bằng dataset liên quan đến SIEM. Hoàn thiện ở Phase 2. |

### TN4: Dynamic Playbook + Approve/Reject (ĐANG PHÁT TRIỂN — Phase 2)

Thay vì hệ thống tự động block IP (Auto-Response) có rủi ro false positive cao, dự án áp dụng triết lý "Human-in-the-loop" bằng cách tích hợp trực tiếp nút bấm thực thi vào Telegram.

| Thuộc tính | Chi tiết |
|---|---|
| Telegram InlineKeyboard | Alert gửi về kèm 2 nút bấm: Approve Block IP và Reject |
| Luồng khi Approve | Analyst bấm Approve -> Telegram Bot gọi API Manager -> Kích hoạt Active Response block IP trên firewall Agent |
| Auto-Rollback | Mọi lệnh block có timer 300 giây (5 phút) để tự động gỡ block |
| Quy trình SOC | L1 Analyst đưa ra quyết định dựa trên Confidence, MITRE và Threat Verdict do AI cung cấp |
| Trạng thái | ĐANG PHÁT TRIỂN — Chưa tích hợp hoàn chỉnh. Sẽ triển khai ở Phase 2 (07/06/2026). |

### TN5: NL-to-Threat-Hunting Query — Câu hỏi tự nhiên thành DSL query (ĐANG PHÁT TRIỂN — Phase 2)

Analyst đặt câu hỏi bằng ngôn ngữ tự nhiên qua Telegram bot, AI tạo OpenSearch DSL query tương ứng. Analyst xem xét DSL trước khi thực thi — không có auto-execution.

Ví dụ sử dụng thực tế:
```
Analyst gõ: /query Tìm tất cả process từ ứng dụng Office spawn ra cmd.exe trong 24 giờ qua

AI tạo OpenSearch DSL:
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.parentImage": ["WINWORD.EXE","EXCEL.EXE"] } },
        { "match": { "data.win.eventdata.image": "cmd.exe" } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  },
  "size": 100
}

Bot: "Đã sinh query. Gửi 'yes' để thực thi hoặc 'no' để hủy."
Analyst gửi: yes
Bot thực thi và trả về: "Tìm thấy 3 cảnh báo: [WORKSTATION-01] PowerShell từ WINWORD.EXE..."
```

Trạng thái: ĐANG PHÁT TRIỂN — Chưa triển khai vào hệ thống. Sẽ hoàn thiện ở Phase 2.

### TN6: AI Gap Analysis sau Red Team (ĐANG PHÁT TRIỂN — Phase 2)

Sau khi kiểm thử Red Team hoàn thành, AI so sánh attack timeline của máy tấn công Kali với coverage cảnh báo của SIEM để tìm ra các kỹ thuật chưa được phát hiện.

```
Đầu vào 1 — Attack Timeline (Kali attacker):
  10:30: PowerShell -enc base64 execution
  10:31: Kết nối ra ngoài 192.168.1.5:4444
  10:35: File tạo tại C:\Temp\malware.exe
  10:40: Ghi vào HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Đầu vào 2 — Alert Coverage (query Wazuh Indexer):
  PASS  10:30: Alert #2345 (Sysmon: PowerShell suspicious args)
  MISS  10:31: KHÔNG CÓ CẢNH BÁO (C2 connection không bị phát hiện)
  PASS  10:35: Alert #2346 (FIM: new exe in Temp)
  MISS  10:40: KHÔNG CÓ CẢNH BÁO (Registry persistence không được giám sát)

Đầu ra AI:
{
  "coverage": 0.50,
  "gaps": [
    {
      "buoc": "Kết nối C2 đến 192.168.1.5:4444",
      "rule_missing": "Chưa có rule phát hiện kết nối ra ngoài trên cổng bất thường",
      "recommendation": "Thêm rule cho kết nối outbound đến cổng C2 không chuẩn"
    }
  ],
  "priority_rules_to_add": [
    "Network: Phát hiện kết nối C2 outbound (port 4444, 5555, 8080)",
    "Registry: Giám sát ghi vào Run key"
  ]
}
```

Trạng thái: ĐANG PHÁT TRIỂN — Cơ bản đã thiết kế. Hoàn thiện sau kiểm thử Red Team đầy đủ ở Phase 2.

---

## Detection Engineering

### Custom Decoder (PCRE2 Regex)

File: `manager/decoders/local_decoder.xml`

Vấn đề: Wazuh default decoder auditd-syscall fail khi log thiếu field a0/a1/a2/a3/items — audit.pid không được trích xuất, phá vỡ toàn bộ pipeline correlation trên Linux.

Giải pháp — fallback decoder chain:
```xml
<!-- Trích xuất audit.pid ngay cả khi định dạng log thiếu field -->
<decoder name="auditd-syscall">
  <parent>auditd</parent>
  <regex offset="after_regex"> pid=(\d+)</regex>
  <order>audit.pid</order>
</decoder>
```

Root cause: Log format từ Ubuntu 22.04 bỏ qua a0/a1/a2/a3 khi syscall là execve không có argument. Default decoder dùng regex khớp toàn bộ chuỗi -> fail. Custom decoder chỉ khớp " pid=<digits>" -> luôn thành công.

### Correlation Rules

File: `manager/rules/local_rules.xml`

Triết lý thiết kế rule: không bắt từng sự kiện đơn lẻ — bắt chuỗi hành vi bất thường.

Ví dụ — SSH Brute Force Correlation:
```xml
<!-- Rule "mồi" — bắt từng lần đăng nhập thất bại -->
<rule id="100510" level="3">
  <if_sid>5710</if_sid>
  <description>SSH authentication failure</description>
</rule>

<!-- Correlation rule — bắt pattern: 8 lần thất bại/60 giây cùng source IP -->
<rule id="100512" level="10" frequency="8" timeframe="60">
  <if_matched_sid>100510</if_matched_sid>
  <same_source_ip />
  <description>Remote Brute-Force SSH: multiple auth failures from same IP</description>
  <group>authentication_failures,brute_force,local_brute_force</group>
  <mitre>
    <id>T1110</id>
    <id>T1110.001</id>
  </mitre>
</rule>
```

Ví dụ — LOLBins Detection (certutil -decode):
```xml
<rule id="100520" level="12">
  <if_sid>61600</if_sid>
  <field name="data.win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
  <field name="data.win.eventdata.commandLine" type="pcre2">(?i)-decode</field>
  <description>LOLBin: certutil.exe dùng để giải mã payload — T1140</description>
  <group>lolbins,sysmon_process,windows</group>
  <mitre>
    <id>T1218</id>
    <id>T1140</id>
    <id>T1059.001</id>
  </mitre>
</rule>
```

### MITRE ATT&CK Coverage

| Chiến thuật | Kỹ thuật được bao phủ | Số rule |
|---|---|---|
| Initial Access | T1078, T1110, T1110.001 | 3 |
| Execution | T1059.001, T1218, T1140 | 4 |
| Persistence | T1547.001, T1053.003 | 3 |
| Defense Evasion | T1070.001, T1036 | 2 |
| Credential Access | T1003, T1003.008, T1552.001 | 3 |
| Discovery | T1046, T1595 | 2 |
| Command & Control | T1071, T1071.001, T1095 | 3 |

---

## Automation & Active Response

### Pipeline cảnh báo Telegram

File: `manager/integrations/custom-telegram`

```
Wazuh Alert -> integratord -> Python script
    |
    +-- Query chuỗi ProcessGuid/PID (OpenSearch)
    +-- AbuseIPDB (tra cứu IP)
    +-- VirusTotal (tra cứu hash)
    |
    v
Ollama Llama 3.1 (phân tích AI nội bộ)
    |
    v
Lưu Incident Report JSON tại /var/ossec/reports/
    |
    v
Telegram 4-Block + nút Approve/Reject
```

### Active Response — Block IP với Auto-Rollback

File: `manager/ossec.conf`

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100512,5712,5720</rules_id>
  <timeout>300</timeout>  <!-- Tự động rollback sau 5 phút -->
</active-response>
```

Logic rollback: Thay vì time.sleep() gây treo process, dùng cấu hình <timeout> của Wazuh daemon wazuh-execd — sau 300 giây tự động sinh lệnh "command":"delete" -> iptables -D INPUT -s <IP> -j DROP.

Ràng buộc an toàn:
```
Chặn nếu:    IP ngoài dải private + khớp ngưỡng rule
Không chặn:  192.168.x.x, 10.x.x.x, 172.16-31.x.x (private RFC1918)
Không chặn:  IP của Wazuh Manager (whitelist cứng)
Không chặn:  IP được whitelist thủ công trong cấu hình
```

Hỗ trợ đa hệ điều hành:
```
Linux:   iptables -I INPUT -s <IP> -j DROP
Windows: netsh advfirewall firewall add rule name="WAZUH_BLOCK_<IP>" dir=in action=block remoteip=<IP>
```
## Cấu trúc Repository
```
├───config                      # NƠI CHỨA CẤU HÌNH HỆ THỐNG (Tách biệt hoàn toàn)
│   ├───wazuh-agent
│   │   ├───linux
│   │   │       ossec.conf          # /var/ossec/etc/ossec.conf — kết nối Manager, khai báo localfile auditd/syslog
│   │   │       sysmonconfig.xml    # /etc/sysmon/sysmonconfig.xml — Sysmon for Linux, chức năng tương tự Sysmon trên Windows
│   │   └───windows
│   │           ossec.conf          # C:\Program Files\ossec-agent\ossec.conf — kết nối Manager, đọc Sysmon Event Log, FIM paths
│   │           sysmonconfig.xml    # C:\Windows\sysmonconfig.xml — filter Event ID 1/3/8/10/11/13/22, whitelist process hệ thống
│   │
│   ├───wazuh-dashboard
│   │       opensearch_dashboards.yml  # /etc/wazuh-dashboard/ — URL Indexer (9200), URL Manager API (55000), TLS config
│   │
│   ├───wazuh-indexer
│   │       jvm.options         # /etc/wazuh-indexer/jvm.options — JVM heap size (-Xms/-Xmx), không vượt 50% RAM vật lý
│   │       opensearch.yml      # /etc/wazuh-indexer/opensearch.yml — cluster name, network host, TLS cert paths, port 9200/9300
│   │
│   └───wazuh-manager
│       └───ossec-snippets      # TỐI ƯU HÓA FILE CẤU HÌNH: Gom toàn bộ file XML cấu hình vào đây
│               api-intel-telegram.xml              # /var/ossec/etc/ossec.conf snippet — khai báo Telegram integration hook, level threshold trigger
│               api-intel-virustotal-abuseipdb.xml  # /var/ossec/etc/ossec.conf snippet — khai báo integration hook, rule ID trigger, API key
│               api-intel-virustotal.xml            # /var/ossec/etc/ossec.conf snippet — khai báo VirusTotal integration hook, trigger khi FIM phát hiện file mới
│
├───integrations                # NƠI CHỨA SCRIPT THỰC THI (Gộp nhóm sạch sẽ, không lẫn file config)
│   ├───abuseipdb
│   │       custom-abuseipdb.py     # /var/ossec/integrations/ — tra cứu IP reputation AbuseIPDB API v2, output confidence_score vào alert JSON
│   │
│   ├───active-response
│   │       custom-quarantine.cmd   # Windows AR script — netsh advfirewall block IP, rollback sau 300s
│   │       custom-quarantine.py    # Linux AR script — iptables DROP + auto-unblock, whitelist private range và Manager IP
│   │
│   ├───artificial-intelligence
│   │       custom-telegram.py      # /var/ossec/integrations/ — pipeline chính: query OpenSearch chain→Threat Intel→Ollama AI→format 4-Block→Telegram Bot
│   │
│   └───virustotal
│           virustotal              # /var/ossec/integrations/ — bash wrapper cũ (legacy), thay thế bởi virustotal.py
│           virustotal.py           # /var/ossec/integrations/ — lookup file hash SHA256 qua VirusTotal API v3, output positives/total vào alert JSON
│
├───scripts                     # MÃ LỆNH TỰ ĐỘNG HÓA VÀ VẬN HÀNH
│   └───backup
│       ├───dashboard           # Script backup giao diện và cấu hình cho máy Dashboard
│       ├───indexer             # Script tự động tạo snapshot dữ liệu cho máy Indexer
│       └───manager             # Script backup rule, decoder và cấu hình cốt lõi của máy Manager
│
├───docs                        # TÀI LIỆU KỸ THUẬT HỆ THỐNG
│   ├───architecture
│   │       architecture.png        # Sơ đồ luồng dữ liệu Agent→Manager→Filebeat→Indexer→Dashboard
│   │       ip-plan.png             # Bảng phân hoạch IP: Manager 0.11, Indexer 0.10, Dashboard 0.12, Agent Linux 0.141, Windows 0.171
│   └───playbooks
│           incident-response-playbook.md  # Quy trình xử lý L1→L2→L3: Brute Force, FIM, Suspicious Process, IOC Match
│
└───academic-reports            # TÀI LIỆU BÁO CÁO (Đã chuyển sang .md và gộp báo cáo cá nhân)
    ├───project-overview.md         # Tổng quan dự án, kiến trúc, mục tiêu, phân công nhóm
    ├───integration-report.md       # Báo cáo tính năng AI: enrichment, Telegram, AbuseIPDB, VirusTotal, Active Response
    ├───dashboard-report.md         # Báo cáo Dashboard: field mapping, log sources, API Manager, visualization
    ├───infrastructure-report.md    # Báo cáo hạ tầng: VM, network, Agent, Sysmon, FIM, Syslog
    └───pentest-report.md           # Kết quả Red/Purple Team: alert coverage, gap analysis, rule cần bổ sung
```

## Hướng dẫn triển khai

### Yêu cầu hệ thống

```
Mỗi máy cần:
- Ubuntu Server 22.04 LTS (Manager, Indexer)
- RAM tối thiểu: Manager 4GB, Indexer 8GB
- Ổ cứng: Manager 40GB, Indexer 80GB
- Kết nối mạng nội bộ (cùng LAN hoặc ZeroTier)
- Python 3.10+ (cho AI pipeline)
- Ollama với Llama 3.1:8b (cho AI nội bộ)
```

### 1. Cài Wazuh Manager (192.168.0.11)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
bash wazuh-install.sh --wazuh-server wazuh-1

sudo systemctl status wazuh-manager
sudo systemctl status filebeat
sudo filebeat test output
```

### 2. Cài Wazuh Indexer (192.168.0.10)

```bash
bash wazuh-install.sh --wazuh-indexer wazuh-1 -i

curl -sk -u admin:${ADMIN_PASS} "https://localhost:9200/_cluster/health?pretty"
curl -sk -u admin:${ADMIN_PASS} "https://localhost:9200/_cat/indices/wazuh-alerts-*?v"
```

### 3. Cài Wazuh Dashboard (192.168.0.12)

```bash
bash wazuh-install.sh --wazuh-dashboard wazuh-1 -i
# Truy cập: https://192.168.0.12
```

### 4. Triển khai Custom Decoder & Rules

```bash
sudo cp manager/decoders/local_decoder.xml /var/ossec/etc/decoders/
sudo cp manager/rules/local_rules.xml      /var/ossec/etc/rules/

# Kiểm tra decoder trước khi restart
sudo /var/ossec/bin/wazuh-logtest
# Dán raw log mẫu, kiểm tra Phase 2 output có đúng field không

sudo systemctl restart wazuh-manager
```

### 5. Cài Wazuh Agent + Sysmon (Windows)

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi" -OutFile wazuh-agent.msi
Start-Process msiexec.exe -Args '/i wazuh-agent.msi WAZUH_MANAGER="192.168.0.11" /quiet' -Wait

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
.\Sysmon64.exe -accepteula -i agent-windows\sysmonconfig-windows.xml

Start-Service WazuhSvc
```

### 6. Cài Wazuh Agent + Sysmon for Linux + auditd (Linux — ubuntu-admin)

```bash
# Cài Wazuh Agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor | \
  sudo tee /usr/share/keyrings/wazuh.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update && sudo apt install wazuh-agent
sudo sed -i 's/MANAGER_IP/192.168.0.11/' /var/ossec/etc/ossec.conf

# Cài Sysmon for Linux
wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update && sudo apt install sysmonforlinux
sudo sysmon -accepteula -i agent-windows/sysmonconfig-linux.xml
sudo systemctl enable sysmon && sudo systemctl start sysmon

# Cài auditd
sudo apt install auditd
sudo cp agent-linux/audit/lab.rules /etc/audit/rules.d/
sudo augenrules --load
sudo systemctl restart wazuh-agent
```

### 7. Triển khai AI Pipeline

```bash
# Cài Ollama
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.1:8b

# Cài thư viện Python
pip install opensearch-py httpx python-dotenv requests jsonschema

# Cấu hình biến môi trường
cp .env.example .env
# Điền: OPENSEARCH_USER, OPENSEARCH_PASS, TELEGRAM_TOKEN, ABUSEIPDB_KEY, VT_KEY

# Triển khai integration scripts
sudo cp manager/integrations/custom-telegram.py  /var/ossec/integrations/custom-telegram
sudo cp manager/integrations/custom-abuseipdb.py /var/ossec/integrations/custom-abuseipdb
sudo cp manager/integrations/custom-virustotal.py /var/ossec/integrations/custom-virustotal
sudo chmod +x /var/ossec/integrations/custom-*
sudo chown root:wazuh /var/ossec/integrations/custom-*

# Kiểm tra pipeline
python tests/test_enrichment_manual.py
```

### 8. Kiểm tra end-to-end

```bash
# Kích hoạt test alert trên Linux agent
sudo cat /etc/shadow  # -> trigger audit rule lab_cred

# Kiểm tra alert vào Manager
sudo tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool

# Kiểm tra Indexer nhận document mới
curl -sk -u admin:${ADMIN_PASS} "https://192.168.0.10:9200/wazuh-alerts-*/_count"
```

---

## Kết quả kiểm thử xâm nhập

Pentest đợt 1 (24/05 – 28/05/2026). Người thực hiện: Khoa (Red Team), Thái (AI Automation), Trọng (Dashboard verify). Môi trường: Kali Linux (192.168.0.168) tấn công Windows Victim (192.168.0.171) và Linux Victim ubuntu-admin (192.168.0.141).

### Kết quả kiểm thử Kill Chain

| Kịch bản | MITRE ATT&CK | Kết quả SIEM | Ghi chú |
|---|---|---|---|
| SIEM-1: Nmap Scan từ Kali | T1046, T1595 | Phát hiện — Syslog flow hoạt động end-to-end | Chưa bắt được SYN-only scan (gói tin bị DROP không được log) |
| SIEM-2: SSH Brute Force | T1110.001, T1110 | Phát hiện + Chặn — Active Response iptables, rollback 300 giây | Wazuh rule 5760 trigger sau 8 lần thất bại/60 giây. Block IP Kali thành công |
| SIEM-3: LOLBins certutil | T1218, T1059.001, T1140 | Phát hiện — Custom rule kích hoạt, commandLine được parse | certutil.exe -decode payload. T1218 hiển thị trên heatmap |
| SIEM-4: Persistence (Cron & Registry) | T1053.003, T1547.001 | Phát hiện — FIM alert và Sysmon Event 13 | FIM bắt được /etc/cron.d/update bị sửa. Sysmon bắt Registry Run key |
| SIEM-5: Xóa Event Log | T1070.001 | Phát hiện — Rule 18145 kích hoạt (Level 12) | Lệnh wevtutil cl Security bị phát hiện. Telegram cảnh báo Critical |
| SIEM-6: Đọc /etc/shadow | T1003.008, T1552.001 | Phát hiện — auditd flow hoạt động | auditd rule lab_cred trigger. Custom decoder parse đúng data.audit.key |

### Kết quả kiểm thử tính năng AI

| Tính năng | Thời gian | Kết quả | Bài học kỹ thuật |
|---|---|---|---|
| TN1: AI Alert Enrichment | 24–26/05/2026 | HOÀN THÀNH — AI gom ProcessGuid chain (Event 1,3,11,13), phát hiện T1059+T1547, Telegram 4-Block + nút Approve chạy đúng | Cần Start-Sleep giữa các lệnh PowerShell để agent kịp đẩy log |
| TN2: Threat Intel Summarization | 27/05/2026 | HOÀN THÀNH — AbuseIPDB + VT raw JSON được AI tóm tắt thành verdict ngôn ngữ tự nhiên trên Telegram | Bắt buộc xử lý HTTP 429 Rate Limit VT: thêm try-except + time.sleep() |
| TN3: Incident Report Generation | 28/05/2026 | ĐANG PHÁT TRIỂN — File INC-*.json chưa xuất đúng format ổn định (null values). Chuyển sang Phase 2 | JSON Schema contract phải được chốt chặt trước khi implement |
| TN4: Dynamic Playbook + Approve/Reject | — | ĐANG PHÁT TRIỂN — Chưa tích hợp hoàn chỉnh. Sẽ triển khai ở Phase 2 (07/06/2026) | — |
| TN5: NL-to-Threat-Hunting Query | — | ĐANG PHÁT TRIỂN — Chưa triển khai vào hệ thống. Sẽ hoàn thiện ở Phase 2 | — |
| TN6: AI Gap Analysis | — | ĐANG PHÁT TRIỂN — Cơ bản đã thiết kế. Hoàn thiện sau kiểm thử Red Team đầy đủ ở Phase 2 | — |

### Các điểm còn thiếu sót cần cải thiện

| Vấn đề | Mô tả | Giải pháp đề xuất |
|---|---|---|
| Nmap SYN-only scan | Firewall DROP packet không được log — Syslog gateway chỉ log kết nối ESTABLISHED | Thêm `iptables -A INPUT -j LOG --log-prefix "WAZUH_DROP:"` |
| Incident Report generation | TN3 chưa xuất file JSON đúng schema ổn định | Refactor prompt với Few-shot examples, đổi model hoặc train AI bằng SIEM dataset |
| TN4, TN5, TN6 | Chưa triển khai vào hệ thống | Hoàn thiện toàn bộ ở Phase 2 |

---

## Kết quả đạt được

### Checklist nghiệm thu kỹ thuật

| Hạng mục | Trạng thái |
|---|---|
| Wazuh Manager hoạt động ổn định | HOÀN THÀNH |
| Wazuh Indexer (OpenSearch) | HOÀN THÀNH |
| Wazuh Dashboard truy cập được | HOÀN THÀNH |
| Windows Agent + Sysmon online | HOÀN THÀNH |
| Linux Agent + Sysmon for Linux + auditd online | HOÀN THÀNH |
| FIM phát hiện thay đổi file | HOÀN THÀNH |
| Syslog từ gateway device | HOÀN THÀNH (chưa bắt được SYN-only scan) |
| Custom Decoder PCRE2 | HOÀN THÀNH |
| Correlation Rules với MITRE | CƠ BẢN HOÀN THÀNH (cần tinh chỉnh giảm false positive) |
| Telegram Bot cảnh báo thời gian thực | HOÀN THÀNH |
| AbuseIPDB + VirusTotal tích hợp | HOÀN THÀNH |
| Active Response + Auto-rollback | HOÀN THÀNH (các tác vụ cơ bản) |
| TN1: AI Alert Enrichment | HOÀN THÀNH |
| TN2: AI Threat Intel Summarization | HOÀN THÀNH |
| TN3: AI Incident Report Generation | ĐANG PHÁT TRIỂN — Phase 2 |
| TN4: Dynamic Playbook + Approve/Reject | ĐANG PHÁT TRIỂN — Phase 2 |
| TN5: NL-to-Threat-Hunting Query | ĐANG PHÁT TRIỂN — Phase 2 |
| TN6: AI Gap Analysis | ĐANG PHÁT TRIỂN — Phase 2 |
| Dashboard Tổng quan / Endpoint / Network | HOÀN THÀNH |
| Quy trình SOC L1-L2-L3 | HOÀN THÀNH |
| Playbook Brute Force / FIM / LOLBins / IOC | CƠ BẢN HOÀN THÀNH |
| Kiểm thử Red/Purple Team đợt 1 | HOÀN THÀNH |

### Chỉ số hiệu năng

```
Thời gian từ sự kiện endpoint đến Telegram:  < 15 giây (trung bình, bao gồm AI enrichment)
Thời gian Active Response block:             < 15 giây
Thời gian phân tích AI (Llama 3.1 nội bộ):  20–30 giây
Thời gian tự động rollback:                  300 giây (5 phút)
Tỷ lệ false positive (sau tuning lần 1):     < 30% (mục tiêu < 10% sau Phase 2)
Độ phủ kill chain phát hiện:                 5/6 kịch bản PASS (Nmap SYN-only partial)
```

---

## Thành viên nhóm

| Thành viên | Vai trò | Phụ trách kỹ thuật |
|---|---|---|
| Khoa | Leader / Detection Engineer / SOC Architect | Wazuh Manager, Custom Decoder (PCRE2), Correlation Rules, MITRE ATT&CK mapping, thiết kế AI prompt, Red/Purple Team, tổng hợp kỹ thuật |
| Thái | SOC L2 Analyst / Security Automation Engineer | Triển khai code AI pipeline (TN1–TN6), Telegram Bot, AbuseIPDB/VirusTotal, Active Response, Threat Hunting queries, tuning |
| Nghĩa | Infrastructure / Sysadmin / Lab Administrator | Mạng lab, quản lý VM, Wazuh Indexer, Agent Windows/Linux, Sysmon (Windows + Linux), auditd, FIM, Syslog |
| Trọng | SOC L1 Analyst / Dashboard Designer / Playbook Writer | Wazuh Dashboard, visualization, quy trình SOC, Playbook, template incident ticket, SOC drill, slide/demo |

---

## Roadmap — Phase 2

Phase 2 (07/06/2026 – 08/08/2026) nâng cấp từ SIEM thuần túy lên SOAR (Security Orchestration, Automation, Response) và hoàn thiện các tính năng AI còn đang phát triển.

**Hoàn thiện các tính năng AI còn dang dở:**

| Tính năng | Việc cần làm |
|---|---|
| TN3: Incident Report Generation | Đổi model AI hoặc train AI bằng SIEM-specific dataset. Hoàn thiện JSON Schema constraint và validation. |
| TN4: Dynamic Playbook + Approve/Reject | Tích hợp Telegram InlineKeyboard với Active Response. Kiểm thử đầy đủ luồng Approve/Reject. |
| TN5: NL-to-Threat-Hunting Query | Triển khai lệnh /query trên Telegram Bot. Kiểm thử độ chính xác DSL generation trên nhiều kịch bản. |
| TN6: AI Gap Analysis | Hoàn thiện sau kiểm thử Red Team đầy đủ. Tích hợp vào quy trình post-pentest. |

**Nâng cấp năng lực SOAR:**
- Thực thi Playbook tự động (AI tự chọn hành động phản ứng)
- Tích hợp hệ thống ticket (Jira/TheHive)
- Quản lý vụ việc với chuỗi bằng chứng (evidence chain)

**Nâng cấp AI:**
- Fine-tune Llama trên custom security dataset
- Multi-turn conversation (AI giữ ngữ cảnh qua nhiều lượt hỏi)
- Chuyển hoàn toàn sang Ollama Local

**Mở rộng phạm vi giám sát:**
- Cloud monitoring (AWS CloudTrail, Azure AD)
- Web Application Firewall (WAF) log
- Sửa lỗi Nmap SYN-scan gap (thêm iptables LOG rule)
- Giảm tỷ lệ false positive xuống dưới 10%

---

## Lưu ý bảo mật

Repository này chỉ chứa cấu hình template với thông tin nhạy cảm đã được ẩn.
Tất cả API key, password, và certificate phải được lưu trong file .env (không commit lên git).
Active Response và pentest scripts chỉ được chạy trong môi trường lab được kiểm soát.

Trước khi git push, kiểm tra toàn bộ repo:
```bash
grep -r "SecurePassword" .
grep -r "api_key" .
grep -r "bot_token" .
grep -r "sk-ant" .
```

---

## Tài liệu tham khảo

- Wazuh Official Documentation: https://documentation.wazuh.com/current/
- Wazuh Distributed Architecture: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/
- Wazuh Custom Decoders: https://documentation.wazuh.com/current/user-manual/ruleset/custom.html
- Wazuh Active Response: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/
- Wazuh File Integrity Monitoring: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/
- MITRE ATT&CK Enterprise Matrix: https://attack.mitre.org/matrices/enterprise/
- Sysmon Download & Documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysmon for Linux: https://github.com/Sysinternals/SysmonForLinux
- SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
- LOLBins Database: https://lolbas-project.github.io/
- Linux Audit System: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening
- OpenSearch DSL Query Reference: https://opensearch.org/docs/latest/query-dsl/
- Ollama Local LLM Runtime: https://ollama.ai
- AbuseIPDB API v2: https://docs.abuseipdb.com/
- VirusTotal API v3: https://developers.virustotal.com/reference/overview
- python-telegram-bot: https://python-telegram-bot.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- SANS Incident Handlers Handbook: https://www.sans.org/white-papers/33901/
- The SOC Analyst Guidebook — Gerald Auger: ISBN 978-1119875260

---

Phase 1 — Dự án thực tập | 06/05/2026 – 03/06/2026
Nhóm thực hiện: Khoa · Thái · Nghĩa · Trọng

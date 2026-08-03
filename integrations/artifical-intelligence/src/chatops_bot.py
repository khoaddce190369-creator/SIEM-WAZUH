# Tên file: /var/ossec/integrations/chatops_bot.py
#
# CHANGELOG v1 -> v1.1 (Thái, review với Claude):
#   - Thêm validate_dsl(): chặn script query / write-operation trước khi bắn vào Indexer
#   - Ép trần "size" tối đa MAX_RESULT_SIZE, không còn hardcode size=5 đè lên AI
#   - Thêm logging đầy đủ (audit trail): ai search gì, lúc nào, ra bao nhiêu kết quả
#   - Lưu last_update_id ra file để không mất/lặp update khi bot restart
#   - Cắt message nếu vượt giới hạn ký tự của Telegram (4096)
#   - Log traceback thay vì nuốt exception im lặng
# CHANGELOG v1.1 -> v1.2:
#   - Thêm cơ chế hỏi xác nhận yes/no bắt buộc trước khi execute (human-in-the-loop)
#   - Thêm command /query (khớp chuẩn Leader), giữ /search làm alias
#   - Thêm num_ctx=8192 + temperature=0.1 khi gọi Ollama (tránh truncate field reference)
# CHANGELOG v1.2 -> v1.3:
#   - Thêm lớp repair field hallucination bằng code (import từ prompt_nl2query),
#     vì model 8B vẫn hallucinate field kiểu ECS dù đã sửa prompt nhiều lần
#   - Tăng PENDING_TTL_SECONDS 300 -> 900, thêm feedback khi yes/no bị gõ sau khi hết hạn
# CHANGELOG v1.3 -> v1.4 (fix bug "im lặng" — nghiêm trọng):
#   - BUG: extract_search_payload/repair_dsl_fields/is_effectively_empty_query/
#     enforce_size_cap/validate_dsl KHÔNG được bọc try/except trong generate_dsl().
#     Khi model 8B trả về dsl_query không phải dict (string/list/None do model bị rối),
#     is_effectively_empty_query() crash (AttributeError), exception bay thẳng lên
#     start_bot()'s outer try/except -> bot KHÔNG BAO GIỜ gửi lại tin nhắn cho Telegram.
#     Đúng triệu chứng: "Đang phân tích câu hỏi..." rồi im lặng hoàn toàn.
#   - FIX: bọc toàn bộ xử lý sau khi gọi Ollama vào try/except riêng, LUÔN trả về
#     message lỗi rõ ràng cho user thay vì để crash âm thầm. Đây là lớp phòng thủ thứ 1;
#     lớp thứ 2 là các hàm helper trong prompt_nl2query.py giờ tự chống non-dict input.
#   - GIỮ NGUYÊN credentials hardcode theo yêu cầu — sẽ chuyển sang env var sau
# CHANGELOG v1.4 -> v2.0 (chuyển toàn bộ AI sang Gemini API theo yêu cầu Khoa):
#   - THAY Ollama (llama3.1:8b local) -> Gemini API (gemini-2.5-flash-lite), qua module
#     dùng chung gemini_client.py. Lý do: model 8B local liên tục hallucinate field dù
#     đã áp dụng nhiều lớp phòng thủ (repair map, hint injection, sắp xếp lại prompt...).
#   - PHÁT HIỆN QUAN TRỌNG khi migrate: bản Ollama trước đây KHÔNG hề gửi
#     SYSTEM_PROMPT_NL_TO_DSL_V1 (bảng field reference) qua API — payload chỉ có
#     "prompt" (câu hỏi), không có "system". Có thể là 1 nguyên nhân góp phần vào
#     hallucination dai dẳng. Bản Gemini giờ luôn gửi system_instruction riêng biệt,
#     tách bạch rõ ràng khỏi user prompt.
#   - Gemini ép response_mime_type="application/json" (đảm bảo JSON hợp lệ cú pháp
#     mạnh hơn Ollama "format":"json" — vốn chỉ là gợi ý, không phải ràng buộc cứng).
#   - Bỏ verify=False khi gọi AI (không cần nữa vì Gemini dùng cert hợp lệ chuẩn, chỉ
#     Indexer nội bộ mới cần verify=False do self-signed cert).
#   - LƯU Ý: dữ liệu (câu hỏi + field reference) giờ rời khỏi mạng nội bộ, gửi ra
#     Internet tới Gemini API — đã xác nhận với Khoa, chấp nhận được.

import requests
import json
import time
import logging
import traceback
import urllib3

from gemini_client import call_gemini_json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from prompt_nl2query import (
    build_nl_to_dsl_prompt,
    SYSTEM_PROMPT_NL_TO_IR_V1,
    get_known_fields,
    fetch_live_fields_from_indexer,
    build_ir_response_schema,
    compile_ir_to_dsl,
    repair_dsl_fields,
    is_effectively_empty_query,
    query_lost_meaningful_content,
    classify_intent,
    OUT_OF_SCOPE_MESSAGE,
    FORBIDDEN_DSL_KEYS,
)

# ==== CONFIG (giữ hardcode theo yêu cầu, sẽ chuyển env var sau) ====
# !!! LƯU Ý: token dưới đây ĐÃ BỊ LỘ (dán vào chat 2 lần) — PHẢI revoke qua @BotFather
# và thay bằng token mới trước khi coi bot này là an toàn để chạy production.
TELEGRAM_BOT_TOKEN = "8389447737:AAG9BvCu4PsBKM_rQbXlPreQ9efE5rXJKUY"
ALLOWED_CHAT_IDS = [-5332495401]  # ID của Group ChatOps TN5
INDEXER_URL = "https://192.168.0.10:9200/wazuh-alerts-*/_search"
# v2.1: endpoint validate cú pháp thật của OpenSearch — trước đây CHỈ có trong
# test_tn5_queries.py (script test riêng), bot thật CHƯA BAO GIỜ validate cú pháp
# qua chính Indexer trước khi hỏi analyst "yes/no". Suy ra từ INDEXER_URL, không
# cần thêm biến cấu hình riêng (tránh 2 nơi phải sửa khi đổi Indexer).
INDEXER_VALIDATE_URL = INDEXER_URL.replace("_search", "_validate/query?explain=true")
INDEXER_USER = "admin"
INDEXER_PASS = "Wazuh-Admin123."

# ==== GIỚI HẠN AN TOÀN ====
MAX_RESULT_SIZE = 20               # trần cứng, khớp với Rule 4 trong prompt
MAX_TELEGRAM_MSG_LEN = 4000        # Telegram cho phép 4096, chừa buffer
OFFSET_FILE = "/var/ossec/integrations/.tn5_last_update_id"
LOG_FILE = "/var/log/tn5_chatops.log"
PENDING_TTL_SECONDS = 900          # quy trình thực tế (đối chiếu Dev Tools, trao đổi thêm)
                                    # thường mất hơn 5 phút -> tăng từ 300 lên 900

# State trong RAM: chat_id -> {"search_payload":..., "ai_json":..., "ts":..., "nl_question":...}
# Nếu bot restart, các pending confirm đang chờ sẽ mất — chấp nhận được vì
# đây chỉ là read-query chưa execute, không có side-effect nào bị treo lỡ dở.
PENDING_CONFIRMATIONS = {}

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# v2.1: KNOWN_FIELDS giờ là HỢP (union) của field reference tĩnh (system prompt) VÀ
# field THẬT lấy trực tiếp từ mapping Indexer lúc khởi động — giải quyết tận gốc 2 bug
# thật đã gặp do field reference viết tay lệch dữ liệu (thiếu srcuser/dstuser, mô tả
# sai program_name). Nếu Indexer không phản hồi lúc khởi động (fetch_live_fields_from_
# indexer trả về rỗng, fail-safe), tự động fallback về CHỈ field tĩnh — không sập bot.
_static_fields = get_known_fields()
_live_fields = fetch_live_fields_from_indexer(
    "https://192.168.0.10:9200", (INDEXER_USER, INDEXER_PASS)
)
KNOWN_FIELDS = _static_fields | _live_fields

# v2.2 FIX KHẨN CẤP: Gemini response_schema có giới hạn KHÔNG CÔNG BỐ chính thức cho
# số lượng giá trị "enum" — cộng đồng ghi nhận ngưỡng an toàn ~100-120 giá trị, vượt
# qua sẽ lỗi "400 INVALID_ARGUMENT" (đã xảy ra thật khi enum nhảy lên 805 field sau khi
# thêm dynamic mapping). enum gửi cho Gemini PHẢI tách riêng, giữ nhỏ/an toàn — KHÔNG
# được dùng KNOWN_FIELDS (union, 805 field) làm enum trực tiếp.
# SCHEMA_ENUM_FIELDS: CHỈ dùng field tĩnh (54 field, đã chạy ổn định từ đầu dự án) cho
# enum của response_schema. KNOWN_FIELDS (đầy đủ, không giới hạn vì là code Python
# thuần, không đụng API Gemini) vẫn dùng cho repair_dsl_fields/is_effectively_empty_
# query/query_lost_meaningful_content — không lãng phí hoàn toàn công sức dynamic
# mapping, chỉ là KHÔNG đưa thẳng vào enum nữa.
SCHEMA_ENUM_FIELDS = _static_fields

if _live_fields:
    logging.info(
        f"STARTUP | field tĩnh={len(_static_fields)} field live từ Indexer={len(_live_fields)} "
        f"tổng hợp={len(KNOWN_FIELDS)} | enum gửi Gemini CHỈ dùng {len(SCHEMA_ENUM_FIELDS)} "
        f"field tĩnh (giới hạn enum API)"
    )
else:
    logging.warning(
        f"STARTUP | KHÔNG lấy được mapping live từ Indexer lúc khởi động — dùng "
        f"CHỈ field tĩnh ({len(_static_fields)} field). Restart lại bot sau khi Indexer "
        f"khả dụng để có đủ field mới nhất."
    )


# ---------------------------------------------------------------------------
# Offset persistence — tránh mất/lặp update khi bot bị restart bởi systemd
# ---------------------------------------------------------------------------
def load_last_update_id():
    try:
        with open(OFFSET_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def save_last_update_id(update_id):
    try:
        with open(OFFSET_FILE, "w") as f:
            f.write(str(update_id))
    except OSError as e:
        logging.error(f"Không ghi được offset file: {e}")


# ---------------------------------------------------------------------------
# Validate DSL trước khi gửi vào Indexer — không tin tưởng tuyệt đối output AI
# ---------------------------------------------------------------------------
def validate_dsl(search_payload: dict) -> tuple[bool, str]:
    """
    Trả về (is_valid, reason). Kiểm tra:
    1. Không chứa các key nguy hiểm (script, delete, reindex...)
    2. size không vượt trần
    3. có ít nhất 1 điều kiện lọc (không phải match_all trần trụi không time filter)
    """
    payload_str = json.dumps(search_payload).lower()

    for forbidden in FORBIDDEN_DSL_KEYS:
        if forbidden.lower() in payload_str:
            return False, f"Query chứa key bị cấm: '{forbidden}'"

    size = search_payload.get("size", 0)
    if not isinstance(size, int) or size < 0:
        return False, "size không hợp lệ"

    query_block = search_payload.get("query", {})
    if is_effectively_empty_query(query_block):
        return False, "Từ chối query không có điều kiện lọc thật sự (tương đương match_all, rủi ro quá tải indexer)"

    return True, ""


def enforce_size_cap(search_payload: dict) -> dict:
    """Ép size không vượt MAX_RESULT_SIZE, giữ nguyên nếu AI đặt size=0 (aggregation)."""
    current_size = search_payload.get("size", MAX_RESULT_SIZE)
    if current_size != 0:
        search_payload["size"] = min(int(current_size), MAX_RESULT_SIZE)
    return search_payload


def validate_against_indexer(query: dict) -> tuple[bool, str]:
    """
    v2.1: Dùng _validate/query API của chính OpenSearch — xác nhận CÚ PHÁP THẬT,
    khác với validate_dsl() (chỉ kiểm tra CẤU TRÚC bằng code tự viết). Trước đây
    bước này CHỈ tồn tại trong test_tn5_queries.py (script test riêng), bot thật
    chưa từng validate qua Indexer trước khi hỏi analyst yes/no — nghĩa là nếu có
    lỗi cú pháp hiếm gặp lọt qua (vd combination operator lạ), analyst chỉ phát
    hiện SAU khi bấm yes, nhận lỗi thẳng từ Indexer.

    Thiết kế fail-open có chủ đích: nếu Indexer tạm không phản hồi được (mất mạng,
    đang restart...), KHÔNG chặn luồng chính — vẫn cho qua bước confirm như bình
    thường (lớp bảo vệ thật sự vẫn là bước yes/no + validate_dsl() code, không phụ
    thuộc bước này). Chỉ chặn khi Indexer PHẢN HỒI RÕ RÀNG là cú pháp sai.
    """
    try:
        resp = requests.post(
            INDEXER_VALIDATE_URL,
            auth=(INDEXER_USER, INDEXER_PASS),
            json={"query": query},
            verify=False,
            timeout=10,
        )
        data = resp.json()
        if not data.get("valid", True):
            explanations = data.get("explanations", [])
            error = explanations[0].get("error") if explanations else "Không rõ lý do"
            return False, error
        return True, ""
    except requests.RequestException as e:
        logging.warning(f"VALIDATE_INDEXER_UNREACHABLE | err={e} (fail-open, không chặn luồng chính)")
        return True, ""
    except (ValueError, KeyError) as e:
        logging.warning(f"VALIDATE_INDEXER_BAD_RESPONSE | err={e} (fail-open, không chặn luồng chính)")
        return True, ""


# ---------------------------------------------------------------------------
# Bước 1: NL -> gọi AI -> repair field -> validate DSL (CHƯA chạm Indexer)
# ---------------------------------------------------------------------------
def generate_dsl(user_query: str, chat_id: int, username: str):
    """
    Trả về (ok, payload_or_errmsg, ai_json, elapsed_seconds, repair_actions).
    Nếu ok=False, payload_or_errmsg là message lỗi để gửi thẳng cho user.
    Nếu ok=True, payload_or_errmsg là search_payload đã repair + validate, sẵn sàng chờ confirm.

    QUAN TRỌNG (v1.4): toàn bộ phần xử lý SAU khi gọi Ollama được bọc trong try/except
    riêng. Trước đây không có -> 1 exception bất ngờ ở đây (vd model trả shape lạ) sẽ
    bay thẳng lên start_bot(), khiến bot không bao giờ trả lời lại Telegram cho câu đó.
    """
    t0 = time.monotonic()
    logging.info(f"QUERY | user={username} chat={chat_id} nl_question={user_query!r}")

    prompt = build_nl_to_dsl_prompt(user_query)

    try:
        # v2.0: dùng response_schema enum-constrain field (build_ir_response_schema) —
        # Gemini CHỈ ĐƯỢC PHÉP chọn field trong danh sách thật, không thể sinh field lạ
        # nữa (khác hẳn cách cũ chỉ "nhắc" qua prompt rồi chờ code dọn dẹp sau khi sai).
        ai_json = call_gemini_json(
            SYSTEM_PROMPT_NL_TO_IR_V1,
            prompt,
            temperature=0.1,
            response_schema=build_ir_response_schema(SCHEMA_ENUM_FIELDS),
        )
    except Exception as e:
        logging.error(f"GEMINI_ERROR | user={username} err={e}")
        return False, f"❌ Lỗi gọi model AI (Gemini): {e}", None, time.monotonic() - t0, []

    # --- Toàn bộ phần xử lý DSL sau đây được bọc try/except riêng (v1.4) ---
    # Lý do: compile_ir_to_dsl/repair_dsl_fields/is_effectively_empty_query/
    # enforce_size_cap/validate_dsl đều giả định 1 số shape nhất định từ ai_json.
    # Dù đã hardening các hàm này ở prompt_nl2query.py, vẫn giữ lớp phòng thủ
    # ở đây làm lưới an toàn cuối cùng — bot phải LUÔN trả lời, không bao giờ im lặng.
    try:
        # v2.0: compile_ir_to_dsl thay cho extract_search_payload — dịch danh sách
        # điều kiện PHẲNG (field đã enum-constrain) sang OpenSearch DSL thật bằng
        # CODE THUẦN TUÝ, không có AI tham gia bước dịch cấu trúc nữa.
        # repair_actions khởi tạo TRƯỚC, dùng CHUNG cho cả compile_ir_to_dsl (field lạ
        # lọt qua enum — phòng thủ) và repair_dsl_fields (lưới an toàn thứ 2) để
        # is_effectively_empty_query/query_lost_meaningful_content thấy đủ thông tin.
        repair_actions = []
        search_payload = compile_ir_to_dsl(ai_json, KNOWN_FIELDS, repair_actions)

        if "query" in search_payload:
            # Vẫn giữ repair_dsl_fields làm lưới an toàn thứ 2 (lẽ ra luôn no-op vì
            # field đã bị enum-constrain ở tầng Gemini, nhưng không tin tuyệt đối
            # ngay cả khi có ràng buộc API — đề phòng edge case SDK/model).
            search_payload["query"] = repair_dsl_fields(search_payload["query"], KNOWN_FIELDS, repair_actions)

            if is_effectively_empty_query(search_payload["query"]):
                elapsed = time.monotonic() - t0
                logging.warning(
                    f"QUERY_EMPTIED_AFTER_REPAIR | user={username} "
                    f"repair_actions={repair_actions} ai_json={ai_json}"
                )
                removed_desc = "; ".join(repair_actions) if repair_actions else "(không có field nào bị xoá — AI tự sinh query rỗng ngay từ đầu)"
                return (
                    False,
                    "❌ Sau khi loại bỏ các field không hợp lệ, query không còn điều kiện lọc nào "
                    f"(tương đương match_all, bị chặn theo chính sách an toàn). Đã loại: {removed_desc}. "
                    "Vui lòng thử diễn đạt lại câu hỏi cụ thể hơn.",
                    ai_json,
                    elapsed,
                    repair_actions,
                )

            # v1.6: query vẫn còn "hợp lệ về hình thức" (không rỗng) nhưng đã mất sạch
            # nội dung thực chất của câu hỏi (vd hỏi port 445 nhưng field port bị xoá,
            # chỉ còn lọc theo giờ) — nguy hiểm hơn query rỗng vì trông như thành công.
            if query_lost_meaningful_content(search_payload["query"], repair_actions):
                elapsed = time.monotonic() - t0
                logging.warning(
                    f"QUERY_LOST_MEANINGFUL_CONTENT | user={username} "
                    f"repair_actions={repair_actions} final_query={search_payload['query']}"
                )
                removed_desc = "; ".join(repair_actions)
                return (
                    False,
                    "❌ Sau khi loại các field không hợp lệ, query chỉ còn lại điều kiện "
                    "thời gian — mất hết nội dung chính của câu hỏi (đã loại: "
                    f"{removed_desc}). Nếu chạy sẽ trả về MỌI alert trong khung giờ thay vì "
                    "đúng điều bạn hỏi, nên bị chặn. Vui lòng thử diễn đạt lại cụ thể hơn "
                    "(vd nêu rõ tên field, giá trị chính xác).",
                    ai_json,
                    elapsed,
                    repair_actions,
                )

        search_payload = enforce_size_cap(search_payload)

        is_valid, reason = validate_dsl(search_payload)
        elapsed = time.monotonic() - t0
        if not is_valid:
            logging.warning(f"REJECTED_DSL | user={username} reason={reason} payload={search_payload}")
            return False, f"❌ Query bị từ chối bởi lớp validate: {reason}", ai_json, elapsed, repair_actions

        # v2.1: validate cú pháp THẬT qua chính Indexer, trước khi hỏi analyst yes/no.
        # Khác với validate_dsl() ở trên (chỉ kiểm tra cấu trúc bằng code tự viết).
        indexer_valid, indexer_reason = validate_against_indexer(search_payload.get("query", {}))
        if not indexer_valid:
            logging.warning(f"REJECTED_BY_INDEXER_VALIDATE | user={username} reason={indexer_reason}")
            return (
                False,
                f"❌ Query không hợp lệ cú pháp theo chính Indexer: {indexer_reason}. "
                "Vui lòng thử diễn đạt lại câu hỏi.",
                ai_json,
                elapsed,
                repair_actions,
            )

        if repair_actions:
            logging.info(f"FIELD_REPAIRED | user={username} actions={repair_actions}")

        logging.info(f"DSL_GENERATED | user={username} elapsed={elapsed:.2f}s dsl={json.dumps(search_payload)}")
        return True, search_payload, ai_json, elapsed, repair_actions

    except Exception as e:
        # LƯỚI AN TOÀN CUỐI: bất kỳ lỗi không lường trước nào ở bước xử lý DSL cũng
        # phải trả lời được cho Telegram, không được để bot im lặng.
        elapsed = time.monotonic() - t0
        logging.error(
            f"DSL_PROCESSING_CRASH | user={username} err={e} ai_json={ai_json!r}\n"
            f"{traceback.format_exc()}"
        )
        return (
            False,
            "❌ Lỗi xử lý DSL không lường trước được (đã ghi log chi tiết để debug). "
            "Vui lòng thử lại hoặc diễn đạt câu hỏi khác.",
            ai_json,
            elapsed,
            [],
        )


def format_confirmation_prompt(user_query: str, search_payload: dict, ai_json: dict,
                                elapsed: float, repair_actions: list) -> str:
    explanation = ai_json.get("explanation", "") if isinstance(ai_json, dict) else ""
    caveats = ai_json.get("caveats") if isinstance(ai_json, dict) else None
    dsl_preview = json.dumps(search_payload, ensure_ascii=False, indent=2)
    if len(dsl_preview) > 2500:
        dsl_preview = dsl_preview[:2500] + "\n...(rút gọn)"

    msg = (
        f"🔎 *Câu hỏi:* {user_query}\n"
        f"*AI diễn giải:* {explanation}\n"
    )
    if caveats and str(caveats).lower() != "null":
        msg += f"⚠️ _{caveats}_\n"
    if repair_actions:
        msg += "🔧 _Đã tự động điều chỉnh field:_\n"
        for action in repair_actions:
            msg += f"   • {action}\n"
    msg += (
        f"⏱️ Thời gian sinh query: {elapsed:.2f}s\n\n"
        f"*DSL sẽ chạy:*\n```json\n{dsl_preview}\n```\n\n"
        f"👉 Reply `yes` để thực thi hoặc `no` để huỷ."
    )
    return msg


# ---------------------------------------------------------------------------
# Bước 2: chạy search_payload đã được confirm vào Indexer -> format kết quả
# ---------------------------------------------------------------------------
def get_nested_value(source: dict, dotted_path: str):
    """Lấy giá trị theo dot-path từ _source, vd 'data.srcip.keyword' -> source['data']['srcip'].
    LƯU Ý: '.keyword' KHÔNG phải 1 path lồng thật trong _source — nó chỉ là 1 sub-mapping
    (multi-field) dùng khi QUERY, giá trị thật vẫn nằm ở field gốc không có .keyword. Nên
    phải bỏ suffix '.keyword' trước khi duyệt _source, nếu không sẽ luôn ra None."""
    path = dotted_path[:-len(".keyword")] if dotted_path.endswith(".keyword") else dotted_path
    node = source
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def run_search(search_payload: dict, ai_json: dict, username: str) -> str:
    try:
        os_resp = requests.post(
            INDEXER_URL,
            auth=(INDEXER_USER, INDEXER_PASS),
            json=search_payload,
            verify=False,  # self-signed cert nội bộ — xem xét trỏ CA cert riêng sau
            timeout=30,
        )
        os_resp.raise_for_status()
        hits_body = os_resp.json().get("hits", {})
        hits = hits_body.get("hits", [])
        # QUAN TRỌNG: dùng hits.total.value để đếm, KHÔNG dùng len(hits) — khi câu hỏi
        # kiểu "có bao nhiêu..." AI đặt size=0 để tối ưu (chỉ cần đếm, không cần tải data),
        # lúc đó hits (mảng document) LUÔN RỖNG dù có hàng trăm/nghìn kết quả khớp thật sự.
        # len(hits) trong trường hợp đó sẽ luôn ra 0 — sai hoàn toàn, hiển thị nhầm "0 kết quả"
        # dù thực ra có rất nhiều. track_total_hits:true (thêm ở compile_ir_to_dsl) đảm bảo
        # con số này chính xác kể cả khi vượt ngưỡng mặc định 10000 của OpenSearch.
        total_value = hits_body.get("total", {}).get("value", len(hits))
    except requests.RequestException as e:
        logging.error(f"INDEXER_ERROR | user={username} err={e}")
        return f"❌ Lỗi truy vấn Indexer: {e}"
    except Exception as e:
        logging.error(f"RUN_SEARCH_CRASH | user={username} err={e}\n{traceback.format_exc()}")
        return f"❌ Lỗi không lường trước khi thực thi query (đã ghi log): {e}"

    logging.info(f"RESULT | user={username} total={total_value} returned={len(hits)} dsl={json.dumps(search_payload)}")

    # Lấy danh sách field AI tự nói là sẽ trả về (fields_returned) để hiển thị THÊM, ngoài
    # rule/agent/description mặc định — trước đây LUÔN chỉ show 3 field cố định này dù câu
    # hỏi thật sự cần thấy field khác (IP, user, path...) -> analyst tìm đúng docs vẫn
    # không thấy được câu trả lời vì field quan trọng nhất không hề được hiển thị.
    extra_fields = []
    if isinstance(ai_json, dict):
        for f in ai_json.get("fields_returned", []) or []:
            base = f[:-len(".keyword")] if isinstance(f, str) and f.endswith(".keyword") else f
            if isinstance(base, str) and base not in ("@timestamp", "rule.id", "rule.description", "agent.name") \
                    and base not in extra_fields:
                extra_fields.append(base)

    if not hits and total_value > 0:
        # size=0 (câu hỏi đếm/thống kê) — không có document nào để liệt kê, chỉ báo tổng số.
        result_msg = f"✅ *Đã thực thi.* Tổng số khớp: *{total_value}* (query dùng size=0, chỉ đếm, không liệt kê chi tiết).\n"
    else:
        result_msg = f"✅ *Đã thực thi.* Tổng số khớp: {total_value}, hiển thị {len(hits)} kết quả:\n"
        for i, hit in enumerate(hits):
            src = hit.get("_source", {})
            rule_id = src.get("rule", {}).get("id")
            agent_name = src.get("agent", {}).get("name")
            rule_desc = src.get("rule", {}).get("description", "")
            ts = src.get("@timestamp", "")
            line = f"[{i+1}] {ts} | Rule {rule_id} | Agent: {agent_name} | {rule_desc}"

            extras = []
            for field_path in extra_fields:
                val = get_nested_value(src, field_path)
                if val not in (None, "", []):
                    extras.append(f"{field_path}={val}")
            if extras:
                line += " | " + " ".join(extras)

            result_msg += line + "\n"

    if len(result_msg) > MAX_TELEGRAM_MSG_LEN:
        result_msg = result_msg[:MAX_TELEGRAM_MSG_LEN] + "\n...(kết quả bị cắt bớt, thu hẹp câu hỏi để xem đầy đủ)"

    return result_msg


def purge_expired_pending():
    now = time.monotonic()
    expired = [cid for cid, v in PENDING_CONFIRMATIONS.items() if now - v["ts"] > PENDING_TTL_SECONDS]
    for cid in expired:
        del PENDING_CONFIRMATIONS[cid]
        logging.info(f"PENDING_EXPIRED | chat={cid}")


# ---------------------------------------------------------------------------
# Telegram polling loop
# ---------------------------------------------------------------------------
def send_telegram_message(chat_id: int, text: str):
    """
    Gửi tin nhắn Telegram với parse_mode=Markdown. Nếu Telegram từ chối vì lỗi
    parse entities (rất hay gặp vì text động — rule.description lấy thẳng từ
    Wazuh index, hoặc explanation do LLM tự sinh — chứa ký tự đặc biệt không
    cân *_`[]), TỰ ĐỘNG gửi lại bằng plain text (không parse_mode) thay vì bỏ
    cuộc. Đây chính là nguyên nhân bug "bấm yes không thấy phản hồi gì": trước
    đây lỗi 400 chỉ được log, không bao giờ tới tay user.
    """
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        )
        if resp.ok:
            return

        body = resp.text
        logging.warning(f"TELEGRAM_SEND_MARKDOWN_FAIL | chat={chat_id} resp={body}")

        # "can't parse entities" là lỗi format Markdown, không phải lỗi mạng/token/quyền
        # -> an toàn để fallback plain text. Lỗi khác (401/403/blocked...) thì fallback
        # cũng vô hại, chỉ là sẽ fail lần nữa và được log riêng.
        fallback_resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": chat_id, "text": text},  # không parse_mode -> plain text
            timeout=15,
        )
        if not fallback_resp.ok:
            logging.error(
                f"TELEGRAM_SEND_FAIL_EVEN_PLAINTEXT | chat={chat_id} "
                f"markdown_err={body} plaintext_err={fallback_resp.text}"
            )
        else:
            logging.info(f"TELEGRAM_SEND_FALLBACK_PLAINTEXT_OK | chat={chat_id}")

    except requests.RequestException as e:
        logging.error(f"TELEGRAM_SEND_EXCEPTION | chat={chat_id} err={e}")


def start_bot():
    print("SecChatOps Bot đã khởi động...")
    logging.info("BOT_START")
    last_update_id = load_last_update_id()
    loop_count = 0

    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
            resp = requests.get(
                url, params={"timeout": 10, "offset": last_update_id}, timeout=15
            ).json()

            # Heartbeat mỗi ~60 vòng lặp (~60-120s tuỳ có update hay không) — giúp phân
            # biệt "bot còn sống nhưng không nhận được tin nhắn nào" (vd Telegram Privacy
            # Mode chặn tin nhắn thường không phải lệnh/reply) với "process bị treo/chết
            # hoàn toàn" (không log gì nữa, kể cả heartbeat). Trước đây log dừng đột ngột
            # không rõ nguyên nhân là do đâu trong 2 khả năng này.
            loop_count += 1
            if loop_count % 60 == 0:
                logging.info(f"BOT_ALIVE | loop={loop_count} pending_confirmations={len(PENDING_CONFIRMATIONS)}")

            purge_expired_pending()

            for result in resp.get("result", []):
                last_update_id = result["update_id"] + 1
                save_last_update_id(last_update_id)

                msg = result.get("message", {})
                chat_id = msg.get("chat", {}).get("id")
                username = msg.get("from", {}).get("username", "unknown")
                text = msg.get("text", "").strip()
                text_lower = text.lower()

                if chat_id is None or chat_id not in ALLOWED_CHAT_IDS:
                    if chat_id is not None:
                        logging.warning(f"UNAUTHORIZED_CHAT | chat_id={chat_id} text={text!r}")
                    continue

                # Log MỌI tin nhắn hợp lệ nhận được, kể cả loại không khớp handler nào bên
                # dưới — để lần sau debug chỉ cần grep "MSG_RECEIVED" là biết chắc Telegram
                # CÓ gửi tin nhắn tới bot hay không, thay vì suy đoán giữa "không nhận được"
                # (vd do Privacy Mode chặn) và "nhận rồi nhưng xử lý bị treo/lỗi".
                logging.info(f"MSG_RECEIVED | user={username} chat={chat_id} text={text!r}")

                # --- Bước xác nhận (bắt buộc, human-in-the-loop) ---
                if chat_id in PENDING_CONFIRMATIONS:
                    pending = PENDING_CONFIRMATIONS[chat_id]

                    if text_lower == "yes":
                        del PENDING_CONFIRMATIONS[chat_id]
                        send_telegram_message(chat_id, "⏳ *Đang thực thi query đã xác nhận...*")
                        final_answer = run_search(pending["search_payload"], pending["ai_json"], username)
                        send_telegram_message(chat_id, final_answer)
                        continue

                    elif text_lower == "no":
                        del PENDING_CONFIRMATIONS[chat_id]
                        logging.info(f"CANCELLED | user={username} chat={chat_id}")
                        send_telegram_message(chat_id, "🚫 Đã huỷ query.")
                        continue

                    else:
                        send_telegram_message(
                            chat_id,
                            "⚠️ Bạn đang có một query chờ xác nhận. "
                            "Reply `yes` để thực thi, `no` để huỷ, trước khi gửi câu hỏi mới.",
                        )
                        continue

                # --- Nhận câu hỏi mới: hỗ trợ cả /query (chuẩn Leader) và /search (alias) ---
                query = None
                for cmd in ("/query ", "/search "):
                    if text.startswith(cmd):
                        query = text[len(cmd):].strip()
                        break

                if query is not None:
                    if not query:
                        send_telegram_message(chat_id, "⚠️ Vui lòng nhập câu hỏi sau /query")
                        continue

                    # v2.1: Intent classification TRƯỚC khi gọi Gemini — chặn sớm câu hỏi
                    # ngoài phạm vi (health-check hạ tầng), tiết kiệm ~27s + chi phí token
                    # thay vì cố ép Gemini sinh DSL cho câu hỏi không có dữ liệu để trả lời
                    # (ca thật: "Indexer có đang active không" -> luôn ra 0 kết quả dù DSL
                    # đúng cú pháp, vì Indexer không phải Wazuh agent được giám sát).
                    intent = classify_intent(query)
                    if intent == "out_of_scope":
                        logging.info(f"INTENT_OUT_OF_SCOPE | user={username} question={query!r}")
                        send_telegram_message(chat_id, OUT_OF_SCOPE_MESSAGE)
                        continue

                    send_telegram_message(chat_id, "⏳ *Đang phân tích câu hỏi...*")

                    # generate_dsl() giờ LUÔN trả về tuple hợp lệ, không bao giờ raise
                    # (đã bọc try/except toàn bộ bên trong) — nhưng vẫn giữ try/except ở
                    # đây làm lớp phòng thủ cuối cùng, tuyệt đối không để bot im lặng.
                    try:
                        ok, payload_or_err, ai_json, elapsed, repair_actions = generate_dsl(
                            query, chat_id, username
                        )
                    except Exception as e:
                        logging.error(
                            f"GENERATE_DSL_UNCAUGHT | user={username} err={e}\n{traceback.format_exc()}"
                        )
                        send_telegram_message(
                            chat_id,
                            "❌ Lỗi hệ thống không lường trước được khi xử lý câu hỏi. "
                            "Đã ghi log chi tiết, vui lòng thử lại hoặc báo Thái kiểm tra log.",
                        )
                        continue

                    if not ok:
                        send_telegram_message(chat_id, payload_or_err)
                        continue

                    PENDING_CONFIRMATIONS[chat_id] = {
                        "search_payload": payload_or_err,
                        "ai_json": ai_json,
                        "ts": time.monotonic(),
                        "nl_question": query,
                    }
                    confirm_msg = format_confirmation_prompt(
                        query, payload_or_err, ai_json, elapsed, repair_actions
                    )
                    send_telegram_message(chat_id, confirm_msg)

                # --- Gõ yes/no nhưng KHÔNG có pending nào (đã hết hạn hoặc gõ nhầm lúc) ---
                elif text_lower in ("yes", "no"):
                    send_telegram_message(
                        chat_id,
                        "⚠️ Không có query nào đang chờ xác nhận (có thể đã hết hạn sau "
                        f"{PENDING_TTL_SECONDS // 60} phút). Vui lòng gửi lại câu hỏi bằng /query.",
                    )

            time.sleep(1)

        except Exception as e:
            logging.error(f"BOT_LOOP_ERROR | {e}\n{traceback.format_exc()}")
            time.sleep(5)


if __name__ == "__main__":
    start_bot()

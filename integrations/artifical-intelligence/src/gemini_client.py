# Tên file: /var/ossec/integrations/gemini_client.py
#
# Module dùng chung để gọi Gemini API — thay thế hoàn toàn Ollama theo yêu cầu Khoa.
# Dùng chung giữa chatops_bot.py (TN5 - NL to Query) và gapanalyst_app.py (TN6 - Gap
# Analysis), tránh lặp code cấu hình client ở 2 nơi.
#
# Model: gemini-3.5-flash-lite.
# !!! LƯU Ý (Claude, review 10/7): comment gốc ở đây mô tả model là "gemini-2.5-flash-lite
# — rẻ/nhanh nhất dòng 2.5, free tier" nhưng GEMINI_MODEL bên dưới đang set "gemini-3.5-
# flash-lite" — đây LÀ model có thật (không phải lỗi gõ), nhưng thuộc dòng 3.5, đắt hơn
# ~5.6 lần so với 2.5-flash-lite. CẦN THÁI/KHOA XÁC NHẬN: có đúng ý dùng bản 3.5 (mạnh
# hơn, đắt hơn) hay ý định ban đầu là "gemini-2.5-flash-lite" như comment mô tả? Giữ
# nguyên giá trị hiện tại, KHÔNG tự ý đổi, vì đây là quyết định chi phí/chất lượng cần
# người có thẩm quyền quyết định, không phải bug code để tự sửa.
#
# free tier miễn phí input/output trong giới hạn rate limit, paid tier cũng rất rẻ (~$0.10/1M
# input, $0.40/1M output token, tính tới 07/2026 — SỐ NÀY ÁP DỤNG CHO gemini-2.5-flash-lite,
# CHƯA XÁC NHẬN lại cho gemini-3.5-flash-lite, giá có thể khác). Hỗ trợ input tới 1M token nên
# KHÔNG còn lo vấn đề cắt cụt field reference như num_ctx=2048 mặc định của Ollama trước đây.
#
# LƯU Ý QUAN TRỌNG (khác biệt với Ollama):
#   - Gemini là API GỌI RA INTERNET, không còn chạy local trong mạng LAN như Ollama.
#     Câu hỏi + field reference sẽ rời khỏi mạng nội bộ -> đã xác nhận với Khoa việc
#     này chấp nhận được, không cần verify=False cho SSL nữa (Google dùng cert hợp lệ).
#   - system_instruction được truyền RIÊNG BIỆT qua tham số của API, KHÔNG bị trộn
#     lẫn vào user prompt như lỗ hổng cũ ở chatops_bot.py (Ollama payload trước đây
#     KHÔNG hề gửi SYSTEM_PROMPT_NL_TO_DSL_V1 — chỉ gửi mỗi câu hỏi, có thể là 1
#     nguyên nhân góp phần vào field hallucination dai dẳng bấy lâu).
#     [Claude, review 10/7]: ĐÃ XÁC NHẬN đây chính xác LÀ nguyên nhân chính, không chỉ
#     "góp phần" — payload Ollama cũ hoàn toàn thiếu key "system", verify bằng cách replay
#     lại đúng payload cũ và kiểm tra text field reference không hề xuất hiện. Xem
#     CHANGELOG v1.8 trong chatops_bot.py.
#   - response_mime_type="application/json" ép Gemini LUÔN trả JSON hợp lệ cú pháp
#     (khác với Ollama "format":"json" chỉ là gợi ý, đôi khi vẫn lệch).

import json
import logging
from google import genai
from google.genai import types

# !!! THAY API KEY THẬT VÀO ĐÂY trước khi deploy — lấy tại https://aistudio.google.com/apikey
# Giữ hardcode theo đúng convention của các file khác trong hệ thống (sẽ chuyển env var sau).
# !!! LƯU Ý (Claude, review 10/7): key dưới đây ĐÃ BỊ DÁN VÀO CHAT — cùng tình trạng như
# TELEGRAM_BOT_TOKEN ở chatops_bot.py. PHẢI revoke/tạo key mới tại AI Studio trước khi coi
# đây là an toàn để chạy production, dù convention hiện tại là "hardcode, chuyển env var sau".
GEMINI_API_KEY = "..."

GEMINI_MODEL = "gemini-3.5-flash-lite"

_client = genai.Client(api_key=GEMINI_API_KEY)


def call_gemini_json(system_prompt: str, user_prompt: str, temperature: float = 0.1,
                      response_schema: dict = None) -> dict:
    """
    Gọi Gemini với system_instruction tách riêng khỏi user_prompt, ép output JSON
    hợp lệ cú pháp, trả về dict đã parse.

    Args:
        system_prompt: Toàn bộ instruction cố định (field reference, rules...).
        user_prompt: Phần động theo từng request (câu hỏi analyst, context...).
        temperature: 0.1 mặc định — ưu tiên bám sát field reference, giảm "sáng tạo".
        response_schema: (tuỳ chọn) JSON schema ép cấu trúc output CHẶT hơn nữa —
            dùng cho các tác vụ có schema cố định, biết trước (vd phân tích incident
            trả về đúng severity/attack_summary/mitre_techniques...). Với TN5 (DSL
            tự do, cấu trúc bool query linh hoạt) KHÔNG dùng tham số này.

    Raises:
        json.JSONDecodeError: nếu response không phải JSON hợp lệ (hiếm, vì đã ép
            response_mime_type, nhưng có thể xảy ra nếu bị safety filter chặn giữa chừng).
        Exception: các lỗi khác từ SDK (network, quota vượt rate limit, auth sai key...).
            Bên gọi (chatops_bot.py, gapanalyst_app.py) PHẢI bọc try/except quanh hàm
            này — không tự bắt exception ở đây để bên gọi tự quyết cách xử lý/log phù
            hợp với từng ngữ cảnh (Telegram reply vs. print ra console).
    """
    config_kwargs = {
        "system_instruction": system_prompt,
        "temperature": temperature,
        "response_mime_type": "application/json",
    }
    if response_schema is not None:
        config_kwargs["response_schema"] = response_schema

    response = _client.models.generate_content(
        model=GEMINI_MODEL,
        contents=user_prompt,
        config=types.GenerateContentConfig(**config_kwargs),
    )

    # Log usage để theo dõi chi phí — khác với Ollama chạy local miễn phí, Gemini tính
    # phí theo token (dù rẻ), nên cần theo dõi để tránh bất ngờ về hoá đơn cuối tháng.
    usage = getattr(response, "usage_metadata", None)
    if usage:
        logging.info(
            f"GEMINI_USAGE | model={GEMINI_MODEL} "
            f"input_tokens={usage.prompt_token_count} "
            f"output_tokens={usage.candidates_token_count} "
            f"total_tokens={usage.total_token_count}"
        )

    if not response.text:
        raise ValueError(
            "Gemini trả về response rỗng (có thể bị safety filter chặn hoàn toàn) — "
            f"finish_reason={response.candidates[0].finish_reason if response.candidates else 'unknown'}"
        )

    return json.loads(response.text)

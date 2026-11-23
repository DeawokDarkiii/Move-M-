# FinSec Agent — Nền tảng AI SOC Tự chủ & Vá ảo An toàn (Virtual Patching) cho Fintech

**FinSec Agent** là nền tảng **AI Security Operations Center (AI SOC)** kết hợp **Vá ảo An toàn (Safe Virtual Patching)** được thiết kế chuyên biệt cho hạ tầng thanh toán, ví điện tử và đối soát tài chính (Fintech). Hệ thống cho phép tự động điều tra các cuộc tấn công nhắm vào logic nghiệp vụ API, kiểm định bán kính ảnh hưởng (Blast Radius) trên tập giao dịch sạch lịch sử để đảm bảo **0% chặn nhầm khách hàng thật**, đồng thời đề xuất luật chặn thời gian thực (`<5ms`) và bản vá mã nguồn gốc (Hotfix Diff) theo quy trình **Human-in-the-Loop**.

---

## 1. Bối cảnh & Bài toán giải quyết

Trong vận hành Fintech, các lỗ hổng logic nghiệp vụ API (như **Webhook Replay** cộng tiền ảo, **BOLA/IDOR** đọc trộm số dư ví, **Race Condition** rút tiền lặp gây âm số dư, hay **lộ Internal API Key** đối soát) có thể gây thất thoát tài chính nghiêm trọng chỉ trong vài giây. Tuy nhiên, đội ngũ vận hành thường gặp 3 rào cản lớn:

1. **Vá mã nguồn gốc chậm hơn tốc độ tấn công:** Quy trình tìm lỗi, viết patch, review code và đẩy CI/CD mất nhiều giờ, trong khi kẻ tấn công khai thác tự động theo mili-giây.
2. **Rủi ro chặn nhầm khách hàng thật (False Positives):** Các quy tắc WAF thủ công viết vội trong lúc khẩn cấp rất dễ chặn nhầm giao dịch thanh toán hợp lệ, gây gián đoạn dòng tiền và trải nghiệm người dùng.
3. **Nguy cơ tấn công ngược vào AI SOC (Indirect Prompt Injection):** Kẻ tấn công có thể nhúng mệnh lệnh giả mạo vào `User-Agent` hoặc `request_body` trong HTTP log để đánh lừa các hệ thống phân tích AI tự động bỏ qua cảnh báo hoặc whitelist IP tấn công.

**FinSec Agent** giải quyết đồng thời cả 3 bài toán trên bằng một vòng khép kín: **Phát hiện & Làm sạch Log → Điều tra đa bước trên DB thật → Sinh luật JSON an toàn → Kiểm định Dry-Run trên 300 giao dịch sạch → Con người duyệt kích hoạt / Rollback 1 chạm**.

---

## 2. Đối tượng sử dụng & Giá trị mang lại

| Nhóm vận hành | Vấn đề hiện tại | Giá trị FinSec Agent mang lại |
|---|---|---|
| **SOC Analyst / Incident Responder** | Quá tải cảnh báo rời rạc, phải ghép log HTTP với sổ cái ví thủ công | AI Agent tự động gọi tool truy vấn log + sổ cái + baseline lịch sử, dựng **Attack Kill Chain** gắn nhãn chuẩn **OWASP API Top 10:2023** trong vài giây. |
| **Risk & Payment Operations** | Lo ngại bật luật chặn khẩn cấp sẽ làm lỗi giao dịch khách hàng thật | Bắt buộc chạy **Dry-Run** trên 300 giao dịch hợp lệ lịch sử (`is_clean_baseline = TRUE`), hiển thị minh bạch tỷ lệ chặn tấn công và số giao dịch bị chặn nhầm (`0 / 300`) trước khi duyệt. |
| **Backend / Payment Engineer** | Cần bằng chứng kỹ thuật và hướng xử lý triệt để ở tầng code | Cung cấp **Virtual Patch** cầm máu ngay tại Middleware trong lúc kỹ sư nhận sẵn **Hotfix Code Diff** (kiểu GitHub diff) để vá tận gốc mã nguồn. |

---

## 3. Kiến trúc hệ thống & Luồng hoạt động

```text
  [Traffic Tấn công / Khách hàng thật]
                  │
                  ▼
  ┌────────────────────────────────────────────────────────────┐
  │   Live Dynamic Virtual Patching Middleware (<5ms cache)    │
  │  • Khớp luật ACTIVE (JSON khai báo) → Chặn ngay 403 / 429  │
  │  • Hợp lệ → Cho đi qua vào dịch vụ thanh toán              │
  └──────────────────────────┬─────────────────────────────────┘
                             ▼
  ┌────────────────────────────────────────────────────────────┐
  │        Payment Sandbox APIs & Cơ sở dữ liệu (5 bảng)       │
  │  wallets │ ledger_entries │ api_logs │ policy_rules │ ...  │
  └──────────────────────────┬─────────────────────────────────┘
                             ▼
  ┌────────────────────────────────────────────────────────────┐
  │     Lớp Sanitizer 2 tầng (Chống Indirect Prompt Injection) │
  │  • Phát hiện & cắt ngắn mẫu ép chỉ thị trong log thô       │
  │  • Cô lập dữ liệu trong <UNTRUSTED_RAW_LOG_DATA>           │
  └──────────────────────────┬─────────────────────────────────┘
                             ▼
  ┌────────────────────────────────────────────────────────────┐
  │         AI SOC ReAct Agent (Function Calling, ≤6 bước)     │
  │  1. query_api_logs        2. trace_wallet_ledger           │
  │  3. inspect_actor_baseline 4. dry_run_policy_rule (300 log)│
  └──────────────────────────┬─────────────────────────────────┘
                             ▼
  ┌────────────────────────────────────────────────────────────┐
  │     Human-in-the-Loop SOC Workspace & Public API (/v1)     │
  │  • Duyệt & Kích hoạt luật chặn (Enforce) / Rollback 1 chạm │
  │  • Xem Hotfix Code Diff & Raw API / cURL                   │
  └────────────────────────────────────────────────────────────┘
```

### Công nghệ sử dụng (Tech Stack)
- **Backend & Middleware:** Python, FastAPI, Pydantic, `slowapi` (Rate Limiting), `httpx` (ASGI Traffic Simulation).
- **Cơ sở dữ liệu:** Supabase (PostgreSQL) với cơ chế lưu trữ 5 bảng quan hệ + lớp tương thích SQLite dự phòng.
- **AI SOC Core:** Google Gemini API (`google-genai` Interactions API, `gemini-3.8-flash`) hỗ trợ Function Calling đa bước và ép đầu ra JSON chuẩn Pydantic, kết hợp **Deterministic ReAct Fallback Engine** đảm bảo hệ thống vận hành ổn định ngay cả khi LLM timeout.
- **Frontend Workspace:** Next.js (App Router), React, TypeScript, Tailwind CSS, Lucide Icons.

### Cấu trúc mã nguồn

```text
finsec-agent/
├── backend/
│   ├── app/
│   │   ├── main.py              # Khởi tạo FastAPI, CORS, Rate Limiter, Live Virtual Patching Middleware
│   │   ├── config.py            # Quản lý cấu hình dịch vụ & biến môi trường
│   │   ├── db.py                # Lớp truy cập 5 bảng dữ liệu PostgreSQL (Supabase) / SQLite
│   │   ├── seed.py              # Bộ sinh 5 ví mẫu (10.000.000₫) & 300 log sạch lịch sử
│   │   ├── sandbox/
│   │   │   └── payment_api.py   # 4 API cổng thanh toán mô phỏng có lỗ hổng nghiệp vụ thật
│   │   ├── policy/
│   │   │   └── engine.py        # Bộ thực thi luật JSON khai báo (0% eval/exec) & hàm Dry-Run
│   │   ├── agent/
│   │   │   ├── sanitizer.py     # Bộ lọc 2 lớp phát hiện & cô lập Indirect Prompt Injection
│   │   │   ├── tools.py         # 4 công cụ điều tra trực tiếp dữ liệu từ DB
│   │   │   └── investigator.py  # Vòng lặp ReAct Agent (max_steps=6) + Structured Incident Report
│   │   └── routers/
│   │       └── api_v1.py        # 4 nhóm dịch vụ API công khai (/v1/...) & Simulator
│   ├── sql/
│   │   └── schema.sql           # Lược đồ 5 bảng PostgreSQL & phân quyền
│   └── tests/
│       └── test_finsec_e2e.py   # Bộ kiểm thử tự động toàn trình cho cả 5 kịch bản tấn công
└── frontend/
    └── src/
        ├── app/page.tsx         # Giao diện AI SOC Workspace 3 vùng trực quan
        ├── components/DiffViewer.tsx  # Trình hiển thị Hotfix Code Diff kiểu GitHub
        └── lib/api.ts           # Lớp giao tiếp chuẩn hóa với FinSec API (/v1/*)
```

---

## 4. Các cơ chế kỹ thuật cốt lõi

### 4.1. Ngôn ngữ Luật Khai báo An toàn (Declarative Virtual Patching — Zero `eval()`/`exec()`)
Thay vì để AI sinh mã Python thực thi động (tiềm ẩn lỗ hổng RCE nghiêm trọng), FinSec Agent định nghĩa một chuẩn JSON khai báo chặt chẽ được kiểm duyệt qua Pydantic (`RuleSpec`) với **5 kiểu điều kiện phòng thủ**:

- `DEDUP_BODY_FIELD`: Chặn trùng lặp trường định danh (như `event_id`) dựa trên đối chiếu trực tiếp sổ cái `ledger_entries.tx_ref` và tùy chọn chặn IP nguồn replay.
- `ENFORCE_OWNER_MATCH`: Trích xuất `wallet_id` từ đường dẫn API và đối chiếu `actor_id` (từ JWT/Header) với `wallets.owner_id` trong DB; lệch chủ sở hữu sẽ bị chặn `403`.
- `IP_WHITELIST_FOR_KEY`: Kiểm tra địa chỉ IP gọi khóa nội bộ có nằm trong dải mạng VPC cho phép (ví dụ `10.0.1.0/24`) bằng thư viện `ipaddress` chuẩn; IP bên ngoài bị chặn `403`.
- `CONCURRENCY_LOCK`: Khóa đồng thời theo `actor_id`/`wallet_id` bằng `asyncio.Lock` kết hợp cửa sổ chống lặp 2 giây; các request rút tiền bắn song song bị chặn `429 Too Many Requests`.
- `IP_BLOCKLIST`: Chặn tường minh theo danh sách IP hoặc CIDR khi cần cô lập khẩn cấp.

Ví dụ một luật JSON hợp lệ do AI đề xuất:
```json
{
  "target_path_prefix": "/sandbox/webhook/payment-success",
  "condition_type": "DEDUP_BODY_FIELD",
  "params": {
    "field": "event_id",
    "block_ips": ["45.133.1.99"]
  },
  "action": "BLOCK_403",
  "reason": "Blocked by FinSec AI Policy: Duplicate payment webhook event_id"
}
```

### 4.2. Kiểm định Bán kính Ảnh hưởng (Dry-Run Blast Radius)
Live Middleware và hàm `dry_run_policy_rule()` dùng chung **duy nhất một hàm đánh giá `evaluate_rule()`**:
- Trước khi trình luật lên con người, AI Agent chạy thử luật ứng viên qua toàn bộ **300 dòng `api_logs` có `is_clean_baseline = TRUE`** cùng các dòng log tấn công vừa xảy ra.
- Hệ thống đo 2 chỉ số thật từ DB: **`attack_blocked_rate`** (tỷ lệ chặn chuỗi tấn công, mục tiêu 100%) và **`blocked_clean`** (số giao dịch khách hàng hợp lệ bị chặn nhầm, mục tiêu `0 / 300`).
- Nếu phát hiện `blocked_clean > 0`, AI Agent tự nhận diện các mẫu bị chặn nhầm (`sample_false_positives`), siết chặt điều kiện luật và chạy Dry-Run vòng 2 trước khi đưa ra khuyến nghị cuối cùng.

### 4.3. Lõi AI SOC ReAct Agent với 4 Công cụ Điều tra DB thật
AI Agent không nhận sẵn kết luận mà chỉ nhận một tín hiệu cảnh báo bất thường, sau đó tự chủ lập kế hoạch gọi tối đa 6 bước (Function Calling) qua 4 công cụ:
1. `query_api_logs(path_prefix, ip, actor_id, limit)`: Truy vấn nhật ký HTTP mới nhất đã qua lớp làm sạch `sanitizer.py`.
2. `trace_wallet_ledger(wallet_id)`: Đọc số dư hiện tại và toàn bộ biến động trong `ledger_entries` để phát hiện cộng tiền trùng `tx_ref` hoặc số dư âm do rút lặp.
3. `inspect_actor_baseline(actor_id, api_key_id)`: So sánh dải IP và hành vi endpoint hiện tại với hồ sơ lịch sử `is_clean_baseline = TRUE` của tài khoản hoặc API key đó.
4. `dry_run_policy_rule(rule_spec)`: Mô phỏng luật chặn đề xuất để kiểm chứng an toàn trước khi hoàn tất báo cáo sự cố.

### 4.4. Phòng thủ Indirect Prompt Injection 2 lớp (`sanitizer.py`)
Mọi dữ liệu chuỗi đến từ phía client (`user_agent`, `request_body`) trước khi đưa vào ngữ cảnh LLM đều đi qua 2 lớp bảo vệ:
- **Lớp 1 — Phát hiện & Vô hiệu hóa mẫu tấn công AI:** Quét các cụm từ ép chỉ thị (`ignore previous`, `system override`, `mark as safe`, `whitelist ip`, `disregard security rules`, `set severity to low`...). Khi phát hiện khớp, hệ thống gắn cờ `"prompt_injection_detected": true`, trích xuất bằng chứng và cắt ngắn/ẩn chuỗi độc hại.
- **Lớp 2 — Cô lập ngữ cảnh (Context Isolation):** Bọc toàn bộ log trong thẻ ranh giới `<UNTRUSTED_RAW_LOG_DATA> ... </UNTRUSTED_RAW_LOG_DATA>` kèm chỉ thị hệ thống bất biến yêu cầu LLM tuyệt đối không tuân theo mệnh lệnh bên trong thẻ và nâng mức nghiêm trọng sự cố lên **`CRITICAL`**.

---

## 5. 5 Kịch bản Tấn công Fintech & Ánh xạ OWASP API Top 10

| # | Kịch bản tấn công | Endpoint mục tiêu | Chuẩn OWASP API:2023 | Hậu quả khi chưa vá ảo | Luật Virtual Patch áp dụng |
|---|---|---|---|---|---|
| 1 | **Webhook Replay** (Cộng tiền ảo) | `POST /sandbox/webhook/payment-success` | `API6:2023` Unrestricted Access to Sensitive Business Flows | Gửi lặp cùng `event_id` 5 lần thổi phồng ví `W_1001` từ `10.000.000₫` lên `35.000.000₫`. | `DEDUP_BODY_FIELD` → Trả `403 Forbidden` cho `event_id` trùng / IP replay. |
| 2 | **BOLA / IDOR** (Đọc trộm ví khác) | `GET /sandbox/wallets/{wallet_id}` | `API1:2023` Broken Object Level Authorization | Tài khoản `usr_an` (chủ `W_1001`) đọc trộm số dư và sổ cái của `W_1002`–`W_1005`. | `ENFORCE_OWNER_MATCH` → Trả `403 Forbidden` khi `actor_id != owner_id`. |
| 3 | **Lộ Internal API Key** | `GET /sandbox/admin/settlement` | `API2:2023` / `API5:2023` Broken Auth & Function Level Auth | Khóa đối soát `internal_settlement_key_prod` bị trích xuất dữ liệu tổng tiền từ IP công cộng ngoài VPC. | `IP_WHITELIST_FOR_KEY` → Chỉ cho phép dải `10.0.1.0/24`, IP ngoài trả `403 Forbidden`. |
| 4 | **Race Condition** (Rút tiền lặp TOCTOU) | `POST /sandbox/withdraw` | `API6:2023` Sensitive Business Flows (TOCTOU) | 5 lệnh rút `4.000.000₫` bắn đồng thời vượt qua kiểm tra số dư, kéo ví `W_1001` xuống `-10.000.000₫`. | `CONCURRENCY_LOCK` → Khóa `asyncio.Lock` + cửa sổ 2s theo `actor_id`, trả `429`. |
| 5 | **Indirect Prompt Injection qua Log** | Nhúng vào `User-Agent` & `request_body` | `LLM01` Prompt Injection kết hợp API Exploit | Kẻ tấn công cố ép AI SOC đánh dấu IP tấn công là an toàn và hạ mức cảnh báo xuống `LOW`. | `sanitizer.py` cô lập thẻ `<UNTRUSTED_RAW_LOG_DATA>`, cảnh báo `CRITICAL` và vẫn chặn tấn công. |

---

## 6. Thiết kế Cơ sở Dữ liệu (5 bảng cốt lõi)

1. **`wallets`**: Lưu 5 ví điện tử mô phỏng (`W_1001`–`W_1005` thuộc `usr_an`–`usr_em`) với số dư ban đầu `10.000.000₫`.
2. **`ledger_entries`**: Sổ cái ghi nhận mọi giao dịch `DEPOSIT` / `WITHDRAW` kèm mã tham chiếu `tx_ref` (dùng để AI đối chiếu chênh lệch tiền thật và kiểm tra trùng `event_id`).
3. **`api_logs`**: Nhật ký HTTP đa dịch vụ (`method`, `path`, `status_code`, `ip_address`, `user_agent`, `actor_id`, `api_key_id`, `request_body`) với cột **`is_clean_baseline`** phân tách rõ **300 giao dịch sạch lịch sử** dùng cho Dry-Run và lưu lượng sự cố thực tế.
4. **`policy_rules`**: Danh sách luật Virtual Patching lưu dưới dạng JSON khai báo (`rule_spec`) theo vòng đời trạng thái `DRAFT` → `ACTIVE` → `ROLLED_BACK`.
5. **`incidents`**: Hồ sơ sự cố chuẩn hóa lưu toàn bộ `reasoning_trace`, `attack_timeline`, `owasp_tag`, `proposed_rule`, `dry_run_report`, `hotfix_diff` và trạng thái xử lý (`OPEN` / `MITIGATED`).

---

## 7. Giao diện AI SOC Workspace & Dịch vụ API Công khai

### Giao diện Web SOC Workspace (3 vùng trực quan)
- **Thanh trên cùng — Live Fintech Attack & Traffic Bar:** 4 nút kích hoạt tấn công thật + nút/tùy chọn kết hợp **Prompt Injection qua Log**, nút xanh lá **Gửi giao dịch khách hàng bình thường** (xác minh `200 OK` ngay cả khi luật chặn đang bật), nút **Reset Sandbox**, liên kết mở **Swagger API Docs** (`/docs`), và dải theo dõi số dư thời gian thực của 5 ví.
- **Cột trái — Luồng điều tra của AI Agent (Live Investigation Trace):** Hiển thị từng bước Agent gọi tool theo thứ tự thời gian, Attack Kill Chain gắn nhãn OWASP API Top 10, cảnh báo đỏ khi phát hiện Indirect Prompt Injection và bảng nhật ký HTTP trực tiếp (`200 OK` vs `403/429 BLOCKED`).
- **Cột phải — Phản ứng & Kiểm định an toàn (Human-in-the-Loop Mitigation):** Thẻ kết quả Dry-Run nổi bật (`Chặn tấn công % | Chặn nhầm khách thật: 0 / 300`) kèm 3 tab chuyên biệt:
  1. **Virtual Patch Policy:** Xem luật JSON khai báo và nút **Duyệt & Kích hoạt Luật Chặn** / **Rollback 1 chạm**.
  2. **Hotfix Code Diff:** Bản vá mã nguồn gốc hiển thị màu xanh/đỏ theo chuẩn GitHub Diff.
  3. **Raw API & cURL:** Phản hồi JSON nguyên văn từ API điều tra cùng các câu lệnh `curl` sẵn sàng kiểm chứng.

### 4 nhóm Endpoint Dịch vụ API Công khai (`/v1/*`)
Tất cả endpoint dịch vụ đều được bảo vệ bằng header `X-API-Key`, giới hạn tần suất gọi (`slowapi`) và xuất tài liệu tương tác Swagger UI tại `/docs`:

| Endpoint | Chức năng |
|---|---|
| `POST /v1/logs/ingest` | Tiếp nhận mảng log HTTP JSON từ các hệ thống fintech bên ngoài. |
| `POST /v1/incidents/investigate` | Kích hoạt AI SOC Agent chạy vòng lặp ReAct điều tra, chạy Dry-Run và trả về `IncidentReport` đầy đủ. |
| `POST /v1/policies/{rule_id}/enforce` & `/rollback` | Kích hoạt luật Virtual Patch sang trạng thái `ACTIVE` trong Live Middleware hoặc hoàn tác ngay lập tức về `ROLLED_BACK`. |
| `POST /v1/sandbox/reset` | Dọn sạch luật đang bật, khôi phục số dư 5 ví về `10.000.000₫` và xóa log tấn công cũ trong khi **giữ nguyên toàn bộ 300 dòng `is_clean_baseline`**. |

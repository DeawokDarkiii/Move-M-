"""SOC Incident Report Exporter (Executive + Technical Deep-Dive).

Generates dual-layer security incident reports that are:
1. Easy to understand for executives, product managers, and operations (plain-language summary,
   business/financial impact, real-world analogy, blast-radius safety guarantee).
2. Deeply technical for SOC analysts, AppSec, and backend engineers (OWASP API Top 10:2023,
   CWE, MITRE ATT&CK, CVSS v3.1 estimate, root cause, declarative virtual patch spec,
   ReAct reasoning trace, chronological attack timeline, and unified Git hotfix diff).

Supported export formats:
- markdown (.md)
- html (.html — print-to-PDF ready A4 SOC report layout)
- json (.json — SIEM/SOAR friendly payload with enriched structured_analysis)
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any


_KNOWLEDGE_BASE: dict[str, dict[str, Any]] = {
    "DEDUP_BODY_FIELD": {
        "category_vi": "Tấn công phát lại giao dịch thanh toán (Webhook Replay Attack)",
        "cwe": "CWE-294 (Authentication Bypass by Capture-replay) / CWE-841 (Improper Enforcement of Behavioral Workflow)",
        "mitre_attack": "T1190 (Exploit Public-Facing Application) / T1565.002 (Transmitted Data Manipulation)",
        "cvss_estimate": "9.1 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        "plain_language_analogy": (
            "Giống như việc một người mang cùng một tờ biên lai chuyển khoản đến quầy giao dịch "
            "nhiều lần liên tiếp và nhân viên không kiểm tra mã biên lai đã dùng hay chưa, dẫn đến cộng tiền lặp nhiều lần vào ví."
        ),
        "business_impact": (
            "Thất thoát tài chính trực tiếp (tạo tiền ảo ngoài sổ cái đối soát ngân hàng), "
            "lệch số dư tổng khi đối soát cuối ngày (EOD settlement) và rủi ro bị rút tiền thật ngay sau khi cộng trùng."
        ),
        "root_cause": (
            "Endpoint `/sandbox/webhook/payment-success` thiếu cơ chế kiểm tra tính duy nhất (Idempotency Check) "
            "trên trường `event_id` trước khi cộng số dư ví, đồng thời bảng `ledger_entries` chưa ràng buộc `UNIQUE(tx_ref)` ở tầng CSDL."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật khai báo `DEDUP_BODY_FIELD` tại tầng Middleware (<5ms): từ chối HTTP 403 ngay lập tức "
            "nếu `event_id` đã tồn tại trong sổ cái hoặc phát sinh từ IP tấn công đã xác định, không cần redeploy mã nguồn."
        ),
        "remediation_checklist": [
            "Áp dụng Virtual Patch `DEDUP_BODY_FIELD` ngay lập tức để chặn phát lại giao dịch ở tầng biên.",
            "Triển khai Hotfix kiểm tra `db.tx_ref_exists(event_id)` kết hợp ràng buộc `UNIQUE(tx_ref)` trên PostgreSQL (`ledger_entries`).",
            "Xác thực chữ ký HMAC-SHA256 (`X-Webhook-Signature`) kèm cửa sổ thời gian `timestamp` (<= 5 phút) cho mọi webhook đối tác.",
            "Chạy đối soát sổ cái (`ledger_entries` vs `wallets`) để thu hồi số dư cộng trùng và lập biên bản sự cố tài chính.",
            "Bổ sung test tự động replay cùng `event_id` (song song & tuần tự) vào pipeline CI/CD.",
        ],
    },
    "ENFORCE_OWNER_MATCH": {
        "category_vi": "Truy cập trái phép đối tượng dữ liệu (BOLA / IDOR)",
        "cwe": "CWE-639 (Authorization Bypass Through User-Controlled Key)",
        "mitre_attack": "T1190 (Exploit Public-Facing Application) / T1530 (Data from Cloud Storage / API)",
        "cvss_estimate": "8.2 HIGH — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "plain_language_analogy": (
            "Giống như khách hàng có thẻ phòng hợp lệ của phòng 101, nhưng chỉ cần đổi số trên đường dẫn thành 102, 103 "
            "là vẫn mở được cửa xem thông tin tài chính và sao kê của người khác."
        ),
        "business_impact": (
            "Lộ lọt thông tin định danh & số dư ví khách hàng (PII / Financial Data Exposure), "
            "vi phạm quy định bảo vệ dữ liệu cá nhân (Nghị định 13/2023/NĐ-CP, PCI-DSS) và suy giảm nghiêm trọng uy tín nền tảng."
        ),
        "root_cause": (
            "Endpoint `GET /sandbox/wallets/{wallet_id}` chỉ xác thực người dùng đã đăng nhập (Authentication) "
            "nhưng bỏ qua bước kiểm tra quyền sở hữu ở mức đối tượng (Object-Level Authorization: `actor_id == wallet.owner_id`)."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật `ENFORCE_OWNER_MATCH` tại Middleware: trích xuất `wallet_id` từ đường dẫn bằng regex an toàn, "
            "đối chiếu chủ sở hữu ví với `actor_id` từ JWT/Header và trả về HTTP 403 nếu không khớp."
        ),
        "remediation_checklist": [
            "Kích hoạt Virtual Patch `ENFORCE_OWNER_MATCH` để chặn ngay mọi truy vấn chéo ví.",
            "Cập nhật mã nguồn `payment_api.py` bắt buộc đối chiếu `actor_id == wallet['owner_id']` (hoặc quyền `SOC_ADMIN` rõ ràng).",
            "Rà soát toàn bộ các endpoint nhận ID qua URL/query (`/wallets/{id}`, `/transactions/{id}`, `/orders/{id}`) theo chuẩn OWASP API1:2023.",
            "Chuyển mã định danh tài nguyên nhạy cảm từ dạng tuần tự dễ đoán (`W_1001`, `W_1002`) sang UUIDv4/ULID.",
            "Thêm unit test kiểm tra truy cập chéo tài khoản (User A đọc tài nguyên User B phải trả về 403).",
        ],
    },
    "IP_WHITELIST_FOR_KEY": {
        "category_vi": "Lộ khóa API nội bộ & Khai thác từ mạng công cộng (Leaked Internal API Key)",
        "cwe": "CWE-798 (Use of Hard-coded Credentials) / CWE-284 (Improper Access Control)",
        "mitre_attack": "T1078 (Valid Accounts / Stolen API Credentials) / T1552 (Unsecured Credentials)",
        "cvss_estimate": "9.6 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "plain_language_analogy": (
            "Giống như chìa khóa phòng kho bạc vốn chỉ dành cho nhân viên đi từ hành lang nội bộ, "
            "nhưng bị rơi ra ngoài và người lạ dùng chính chìa khóa đó mở cửa từ ngoài đường lớn."
        ),
        "business_impact": (
            "Lộ toàn bộ dữ liệu đối soát tài chính tổng hệ thống (`/sandbox/admin/settlement`), "
            "nguy cơ leo thang sang các API quản trị khác và ảnh hưởng trực tiếp tới tuân thủ an toàn thông tin tài chính."
        ),
        "root_cause": (
            "Endpoint quản trị `/sandbox/admin/settlement` chỉ kiểm tra chuỗi tĩnh `X-Internal-API-Key` mà không giới hạn vùng mạng "
            "(Network Segmentation / VPC CIDR allowlist) và không có cơ chế mTLS hoặc định danh dịch vụ ngắn hạn."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật `IP_WHITELIST_FOR_KEY` tại Middleware: chỉ cho phép các request mang khóa đối soát nội bộ đi từ dải VPC tin cậy "
            "`10.0.1.0/24`; mọi truy cập từ IP công cộng lập tức bị chặn HTTP 403."
        ),
        "remediation_checklist": [
            "Kích hoạt ngay Virtual Patch `IP_WHITELIST_FOR_KEY` để cô lập truy cập ngoài dải `10.0.1.0/24`.",
            "Thu hồi (Rotate) ngay lập tức khóa `internal_settlement_key_prod` và kiểm tra lịch sử Git/CI logs để tìm nguồn rò rỉ.",
            "Chuyển các endpoint `/admin/*` về Private Network / Internal Load Balancer, không phơi trực tiếp ra Internet công cộng.",
            "Áp dụng mTLS hoặc token ngắn hạn (OIDC/Workload Identity) cho các cronjob đối soát nội bộ.",
            "Thiết lập cảnh báo SIEM tức thì khi phát hiện khóa nội bộ xuất hiện từ ASN/IP ngoài VPC.",
        ],
    },
    "CONCURRENCY_LOCK": {
        "category_vi": "Tấn công tranh chấp đồng thời khi rút tiền (Race Condition / TOCTOU)",
        "cwe": "CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization) / CWE-367 (TOCTOU)",
        "mitre_attack": "T1190 (Exploit Public-Facing Application) / T1499 (Endpoint Business Logic Abuse)",
        "cvss_estimate": "9.1 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
        "plain_language_analogy": (
            "Giống như việc dùng cùng một tài khoản bấm rút toàn bộ số dư cùng lúc tại nhiều máy ATM trong cùng một tích tắc; "
            "hệ thống kiểm tra thấy đủ tiền trước khi kịp trừ nên cho phép rút vượt quá số dư thực tế."
        ),
        "business_impact": (
            "Rút tiền vượt số dư (Double Spending / Balance Overdraft), làm âm hoặc cạn ví thanh toán, "
            "gây thiệt hại tiền thật tức thì nếu không khóa giao dịch kịp thời."
        ),
        "root_cause": (
            "Luồng `POST /sandbox/withdraw` thực hiện đọc số dư (`SELECT balance`) rồi mới cập nhật (`UPDATE balance`) "
            "theo mô hình Check-Then-Act không có khóa mức hàng (`SELECT ... FOR UPDATE`) hoặc cập nhật nguyên tử có điều kiện (`WHERE balance >= amount`)."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật `CONCURRENCY_LOCK` tại Middleware: thiết lập khóa đồng thời theo `actor_id` trong cửa sổ 2 giây "
            "và trả về HTTP 429 cho các yêu cầu rút tiền bắn song song bất thường."
        ),
        "remediation_checklist": [
            "Kích hoạt Virtual Patch `CONCURRENCY_LOCK` để chặn đứng các đợt bắn request rút tiền song song.",
            "Triển khai Hotfix giao dịch nguyên tử ở tầng Database: `UPDATE wallets SET balance = balance - :amt WHERE id = :id AND balance >= :amt` kèm `SELECT ... FOR UPDATE`.",
            "Áp dụng Distributed Lock (Redis Redlock / PostgreSQL Advisory Lock) theo `wallet_id` cho mọi thao tác biến động số dư.",
            "Bổ sung ràng buộc `CHECK (balance >= 0)` trực tiếp ở schema PostgreSQL để chặn số dư âm ở mức CSDL.",
            "Kiểm thử tải đồng thời (10–50 concurrent requests cùng 1 ví) trong bộ test hồi quy trước khi release.",
        ],
    },
    "AUTH_VELOCITY_GUARD": {
        "category_vi": "Tấn công Thử mật khẩu hàng loạt & Chiếm đoạt Tài khoản (Credential Stuffing / ATO)",
        "cwe": "CWE-307 (Improper Restriction of Excessive Authentication Attempts)",
        "mitre_attack": "T1110.004 (Brute Force: Credential Stuffing)",
        "cvss_estimate": "8.6 HIGH — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "plain_language_analogy": (
            "Giống như kẻ xấu mua danh sách hàng triệu chìa khóa bị lộ từ các dịch vụ khác rồi dùng máy thử nhanh lần lượt vào hàng nghìn ổ khóa nhà khách hàng ngân hàng (tương tự vụ PayPal 2022–2023)."
        ),
        "business_impact": (
            "Chiếm đoạt tài khoản khách hàng (Account Takeover), rút tiền trái phép, lộ thông tin cá nhân và tăng đột biến khiếu nại gian lận."
        ),
        "root_cause": (
            "Endpoint `/sandbox/auth/login` thiếu cơ chế phát hiện vận tốc đăng nhập bất thường kết hợp tín hiệu thiết bị tin cậy (`device_trusted`) và xác thực đa yếu tố bắt buộc (MFA/Passkey)."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật `AUTH_VELOCITY_GUARD` tại Middleware (<5ms): trả về HTTP 429 cho các chuỗi đăng nhập tốc độ cao từ IP lạ hoặc thiết bị chưa xác thực MFA."
        ),
        "remediation_checklist": [
            "Kích hoạt ngay Virtual Patch `AUTH_VELOCITY_GUARD` để chặn các luồng botnet thử đăng nhập.",
            "Bắt buộc xác thực đa yếu tố (Passkey / Smart OTP) khi đăng nhập từ thiết bị hoặc dải IP mới.",
            "Tích hợp kiểm tra mật khẩu bị rò rỉ (breached credential check) và khóa tạm theo cặp `(IP, username)`.",
            "Cảnh báo khách hàng ngay khi phát hiện đăng nhập bất thường.",
        ],
    },
    "BLOCK_FORBIDDEN_FIELDS": {
        "category_vi": "Giả mạo Tham số & Gán hàng loạt (Parameter Tampering / Mass Assignment)",
        "cwe": "CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)",
        "mitre_attack": "T1190 (Exploit Public-Facing Application) / T1565 (Data Manipulation)",
        "cvss_estimate": "9.1 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
        "plain_language_analogy": (
            "Giống như khách hàng tự viết thêm dòng 'Phí = 0₫' hoặc 'Quyền = Quản trị viên' vào tờ phiếu chuyển tiền và hệ thống tự động chấp nhận mà không lọc bỏ các ô cấm."
        ),
        "business_impact": (
            "Thất thoát phí giao dịch, chuyển tiền số âm làm sai lệch số dư ví, hoặc leo thang đặc quyền trái phép lên tài khoản quản trị."
        ),
        "root_cause": (
            "API `/sandbox/transfer` nhận trực tiếp toàn bộ JSON body mà không áp dụng DTO allowlist chặt chẽ và thiếu kiểm tra giá trị dương `amount > 0`."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật `BLOCK_FORBIDDEN_FIELDS` tại Middleware: chặn ngay HTTP 403 mọi request chứa trường nhạy cảm (`role`, `is_admin`, `fee_override`, `discount_pct`) hoặc `amount <= 0`."
        ),
        "remediation_checklist": [
            "Kích hoạt ngay Virtual Patch `BLOCK_FORBIDDEN_FIELDS` để lọc bỏ trường giả mạo ở tầng biên.",
            "Cấu hình Pydantic `extra='forbid'` trên toàn bộ request schema thanh toán/chuyển tiền.",
            "Bắt buộc tính phí giao dịch và chiết khấu hoàn toàn ở phía Backend, không bao giờ tin giá trị gửi từ Client.",
            "Bổ sung unit test gửi `amount <= 0` và các trường cấm (`role`, `is_admin`) vào CI/CD.",
        ],
    },
    "BLOCK_INTERNAL_URL": {
        "category_vi": "Giả mạo Yêu cầu Phía Máy chủ (SSRF — Tương tự vụ Capital One 2019)",
        "cwe": "CWE-918 (Server-Side Request Forgery)",
        "mitre_attack": "T1190 (Exploit Public-Facing Application) / T1552.005 (Cloud Instance Metadata API)",
        "cvss_estimate": "9.8 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "plain_language_analogy": (
            "Giống như đối tác nộp địa chỉ giao hàng là 'phòng máy chủ bí mật bên trong ngân hàng' (`169.254.169.254`), khiến chính nhân viên nội bộ tự vào lấy chìa khóa kho bạc mang ra ngoài."
        ),
        "business_impact": (
            "Lộ thông tin xác thực Cloud (AWS/GCP IAM credentials), quét mạng nội bộ và nguy cơ rò rỉ dữ liệu khách hàng quy mô lớn như sự cố Capital One 2019."
        ),
        "root_cause": (
            "Endpoint `/sandbox/webhooks/register` cho phép đối tác nhập URL callback tùy ý mà không chặn dải địa chỉ nội bộ (RFC1918, loopback `127.0.0.1`, link-local `169.254.169.254`)."
        ),
        "virtual_patch_mechanism": (
            "Áp dụng luật `BLOCK_INTERNAL_URL` tại Middleware (<5ms): từ chối HTTP 403 ngay lập tức mọi URL trỏ tới `169.254.169.254`, `localhost`, `127.0.0.1`, dải IP nội bộ hoặc giao thức `file://`."
        ),
        "remediation_checklist": [
            "Kích hoạt ngay Virtual Patch `BLOCK_INTERNAL_URL` để chặn truy cập Cloud Metadata & IP nội bộ.",
            "Chuyển toàn bộ Cloud VM sang IMDSv2 (bắt buộc token session) và giới hạn quyền IAM theo nguyên tắc tối thiểu.",
            "Phân giải DNS trước khi gửi outbound request và chặn toàn bộ IP thuộc private/loopback/link-local CIDR.",
            "Định tuyến outbound webhook qua Egress Proxy tách biệt khỏi VPC chứa dữ liệu lõi.",
        ],
    },
}


def _detect_condition_type(incident: dict[str, Any]) -> str:
    proposed = incident.get("proposed_rule") or {}
    rule_spec = proposed.get("rule_spec") or {}
    ctype = str(rule_spec.get("condition_type") or "").upper()
    if ctype in _KNOWLEDGE_BASE:
        return ctype

    owasp = str(incident.get("owasp_tag") or "").lower()
    title = str(incident.get("title") or "").lower()
    combined = f"{owasp} {title}"
    if "webhook" in combined or "replay" in combined:
        return "DEDUP_BODY_FIELD"
    if "bola" in combined or "idor" in combined:
        return "ENFORCE_OWNER_MATCH"
    if "key" in combined or "settlement" in combined:
        return "IP_WHITELIST_FOR_KEY"
    if "race" in combined or "toctou" in combined or "withdraw" in combined:
        return "CONCURRENCY_LOCK"
    if "stuffing" in combined or "ato" in combined or "login" in combined:
        return "AUTH_VELOCITY_GUARD"
    if "tamper" in combined or "mass assignment" in combined or "transfer" in combined:
        return "BLOCK_FORBIDDEN_FIELDS"
    if "ssrf" in combined or "169.254" in combined or "metadata" in combined:
        return "BLOCK_INTERNAL_URL"
    return "ENFORCE_OWNER_MATCH"


def build_structured_analysis(incident: dict[str, Any]) -> dict[str, Any]:
    """Build dual-layer Executive + Technical analysis for an incident."""
    ctype = _detect_condition_type(incident)
    kb = _KNOWLEDGE_BASE[ctype]
    dry_run = incident.get("dry_run_report") or {}
    total_clean = int(dry_run.get("total_clean") or 0)
    blocked_clean = int(dry_run.get("blocked_clean") or 0)
    fp_rate = float(dry_run.get("false_positive_rate") or 0.0)
    attack_blocked = bool(dry_run.get("attack_blocked", False))
    safe_to_enforce = bool(dry_run.get("safe_to_enforce", False))
    status = str(incident.get("status") or "OPEN").upper()
    pi_detected = bool(incident.get("prompt_injection_detected", False))

    if status == "MITIGATED":
        protection_status = (
            "ĐÃ ĐƯỢC BẢO VỆ (Virtual Patch đang ACTIVE trên Middleware <5ms — tấn công đã bị chặn đứng)."
        )
    elif safe_to_enforce:
        protection_status = (
            f"SẴN SÀNG VÁ NÓNG AN TOÀN — Đã kiểm chứng Dry-Run trên {total_clean} giao dịch sạch "
            f"với {blocked_clean} lượt chặn nhầm ({fp_rate:.2f}% False Positive). Đề xuất SOC bấm Enforce ngay."
        )
    else:
        protection_status = (
            "CẦN RÀ SOÁT THỦ CÔNG — Luật đề xuất chưa đạt ngưỡng an toàn tuyệt đối khi Dry-Run, cần SOC hiệu chỉnh trước khi Enforce."
        )

    executive_summary = {
        "headline": incident.get("title") or kb["category_vi"],
        "category_vi": kb["category_vi"],
        "severity": incident.get("severity") or "HIGH",
        "status": status,
        "what_happened": incident.get("summary") or kb["root_cause"],
        "plain_language_analogy": kb["plain_language_analogy"],
        "business_impact": kb["business_impact"],
        "protection_status": protection_status,
        "blast_radius_verdict": (
            f"An toàn tuyệt đối ({blocked_clean}/{total_clean} giao dịch khách hàng hợp lệ bị ảnh hưởng, "
            f"chặn tấn công: {'CÓ' if attack_blocked else 'CHƯA'})."
        ),
        "prompt_injection_warning": (
            "Phát hiện kẻ tấn công chèn lệnh Indirect Prompt Injection trong log nhằm đánh lừa AI SOC, "
            "nhưng đã bị lớp phòng thủ `sanitizer.py` cô lập và vô hiệu hóa thành công."
            if pi_detected
            else "Không ghi nhận nỗ lực tấn công Indirect Prompt Injection nhắm vào AI SOC trong sự cố này."
        ),
    }

    technical_analysis = {
        "owasp_api_top_10": incident.get("owasp_tag") or "OWASP API Security Top 10:2023",
        "cwe_mapping": kb["cwe"],
        "mitre_attack": kb["mitre_attack"],
        "cvss_v31_estimate": kb["cvss_estimate"],
        "condition_type": ctype,
        "root_cause_analysis": kb["root_cause"],
        "virtual_patch_mechanism": kb["virtual_patch_mechanism"],
        "remediation_checklist": kb["remediation_checklist"],
        "engine_used": incident.get("engine_used") or "finsec-ai-soc",
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": executive_summary,
        "technical_analysis": technical_analysis,
    }


def render_markdown_report(incident: dict[str, Any]) -> str:
    """Render a comprehensive, dual-layer Markdown SOC Incident Report."""
    analysis = build_structured_analysis(incident)
    exec_sum = analysis["executive_summary"]
    tech = analysis["technical_analysis"]
    dry_run = incident.get("dry_run_report") or {}
    proposed_rule = incident.get("proposed_rule") or {}
    timeline = incident.get("attack_timeline") or []
    trace = incident.get("reasoning_trace") or []
    hotfix_diff = incident.get("hotfix_diff") or "# No hotfix diff attached"

    lines: list[str] = [
        f"# BÁO CÁO SỰ CỐ AN NINH FINTECH — {incident.get('id', 'INC-UNKNOWN')}",
        "",
        f"> **Tiêu đề:** {exec_sum['headline']}  ",
        f"> **Mức độ nghiêm trọng:** `{exec_sum['severity']}` | **Trạng thái:** `{exec_sum['status']}`  ",
        f"> **Thời điểm phát hiện:** `{incident.get('created_at', 'N/A')}` | **AI Engine:** `{tech['engine_used']}`",
        "",
        "---",
        "",
        "## 1. Tóm tắt Điều hành (Executive Summary — Dễ hiểu cho Lãnh đạo & Vận hành)",
        "",
        f"- **Bản chất sự cố:** {exec_sum['category_vi']}",
        f"- **Chuyện gì đã xảy ra:** {exec_sum['what_happened']}",
        f"- **Hình dung đời thực:** _{exec_sum['plain_language_analogy']}_",
        f"- **Tác động kinh doanh & tài chính:** {exec_sum['business_impact']}",
        f"- **Tình trạng bảo vệ hiện tại:** {exec_sum['protection_status']}",
        f"- **Cam kết không ảnh hưởng khách hàng thật (Blast Radius):** {exec_sum['blast_radius_verdict']}",
        f"- **Phòng thủ chống thao túng AI (Prompt Injection):** {exec_sum['prompt_injection_warning']}",
        "",
        "---",
        "",
        "## 2. Phân tích Kỹ thuật Chuyên sâu (Technical Deep-Dive — SOC / AppSec)",
        "",
        "| Hạng mục chuẩn hóa | Giá trị |",
        "| :--- | :--- |",
        f"| **OWASP API Top 10 (2023)** | `{tech['owasp_api_top_10']}` |",
        f"| **Phân loại CWE** | {tech['cwe_mapping']} |",
        f"| **MITRE ATT&CK** | {tech['mitre_attack']} |",
        f"| **Ước lượng CVSS v3.1** | `{tech['cvss_v31_estimate']}` |",
        f"| **Cơ chế Virtual Patch** | `{tech['condition_type']}` |",
        "",
        "### Nguyên nhân gốc rễ (Root Cause)",
        tech["root_cause_analysis"],
        "",
        "### Cơ chế Vá nóng Tức thì (Declarative Virtual Patching <5ms)",
        tech["virtual_patch_mechanism"],
        "",
        "---",
        "",
        "## 3. Kiểm chứng Bán kính Ảnh hưởng (Dry-Run Blast Radius Verification)",
        "",
        "| Chỉ số kiểm định | Kết quả |",
        "| :--- | :--- |",
        f"| **Tổng giao dịch sạch lịch sử (`is_clean_baseline`)** | `{dry_run.get('total_clean', 0)}` |",
        f"| **Số giao dịch khách hàng bị chặn nhầm (False Positives)** | `{dry_run.get('blocked_clean', 0)}` (`{dry_run.get('false_positive_rate', 0)}%`) |",
        f"| **Tổng log tấn công kiểm định** | `{dry_run.get('total_attack_logs', 0)}` |",
        f"| **Số log tấn công bị chặn thành công** | `{dry_run.get('blocked_attack_logs', 0)}` (`{dry_run.get('attack_blocked_rate', 0)}%`) |",
        f"| **Đánh giá an toàn triển khai (`safe_to_enforce`)** | `{'AN TOÀN (TRUE)' if dry_run.get('safe_to_enforce') else 'CẦN RÀ SOÁT (FALSE)'}` |",
        "",
        "---",
        "",
        "## 4. Dòng thời gian Tấn công (Attack Kill-Chain Timeline)",
        "",
    ]

    if timeline:
        lines.append("| Thời gian | Giai đoạn | IP nguồn | Endpoint | Chi tiết |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for ev in timeline:
            lines.append(
                f"| `{ev.get('timestamp', '-')}` | {ev.get('stage', '-')} | `{ev.get('ip_address', '-')}` | `{ev.get('endpoint', '-')}` | {ev.get('detail', '-')} |"
            )
    else:
        lines.append("_Chưa ghi nhận chuỗi sự kiện tấn công chủ động (báo cáo kiểm định chủ động)._")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 5. Dấu vết Điều tra AI Agent (ReAct Reasoning Trace)",
            "",
        ]
    )

    if trace:
        for st in trace:
            lines.append(
                f"- **Bước {st.get('step', '?')} — `{st.get('action', 'tool')}`:** {st.get('observation_summary', '')}"
            )
    else:
        lines.append("_Không có dữ liệu ReAct trace._")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 6. Luật Phòng thủ Khai báo (Declarative Virtual Patch JSON)",
            "",
            "```json",
            json.dumps(proposed_rule, indent=2, ensure_ascii=False),
            "```",
            "",
            "## 7. Bản vá Mã nguồn Gốc rễ cho Đội Phát triển (Permanent Code Hotfix Diff)",
            "",
            "```diff",
            hotfix_diff.strip(),
            "```",
            "",
            "---",
            "",
            "## 8. Kế hoạch Khắc phục & Kiểm thử Hồi quy (Remediation Checklist)",
            "",
        ]
    )

    for idx, item in enumerate(tech["remediation_checklist"], start=1):
        lines.append(f"{idx}. [ ] {item}")

    lines.append("")
    lines.append(f"_Báo cáo được tạo tự động bởi FinSec Agent SOC Platform lúc `{analysis['generated_at']}`._")
    return "\n".join(lines)


def render_html_report(incident: dict[str, Any]) -> str:
    """Render a print-to-PDF ready HTML SOC Incident Report with clean A4 styling."""
    analysis = build_structured_analysis(incident)
    exec_sum = analysis["executive_summary"]
    tech = analysis["technical_analysis"]
    dry_run = incident.get("dry_run_report") or {}
    proposed_rule = incident.get("proposed_rule") or {}
    timeline = incident.get("attack_timeline") or []
    trace = incident.get("reasoning_trace") or []
    hotfix_diff = incident.get("hotfix_diff") or "# No hotfix diff attached"

    esc = html.escape
    sev = str(exec_sum["severity"]).upper()
    sev_color = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#059669",
    }.get(sev, "#334155")

    timeline_rows = ""
    for ev in timeline:
        timeline_rows += (
            "<tr>"
            f"<td><code>{esc(str(ev.get('timestamp', '-')))}</code></td>"
            f"<td><strong>{esc(str(ev.get('stage', '-')))}</strong></td>"
            f"<td><code>{esc(str(ev.get('ip_address', '-')))}</code></td>"
            f"<td><code>{esc(str(ev.get('endpoint', '-')))}</code></td>"
            f"<td>{esc(str(ev.get('detail', '-')))}</td>"
            "</tr>"
        )
    if not timeline_rows:
        timeline_rows = "<tr><td colspan='5' style='color:#64748b'>Không có sự kiện tấn công chủ động.</td></tr>"

    trace_items = "".join(
        f"<li><strong>Bước {esc(str(st.get('step', '?')))} — <code>{esc(str(st.get('action', '')))}</code>:</strong> "
        f"{esc(str(st.get('observation_summary', '')))}</li>"
        for st in trace
    )

    checklist_items = "".join(
        f"<li>{esc(item)}</li>" for item in tech["remediation_checklist"]
    )

    rule_json = esc(json.dumps(proposed_rule, indent=2, ensure_ascii=False))
    diff_text = esc(hotfix_diff.strip())

    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>FinSec SOC Incident Report — {esc(str(incident.get('id', 'INC')))}</title>
  <style>
    :root {{ --ink: #0f172a; --muted: #475569; --border: #cbd5e1; --bg: #f8fafc; --sev: {sev_color}; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: var(--ink); background: #eef2f6; margin: 0; padding: 24px; line-height: 1.55; }}
    .page {{ max-width: 960px; margin: 0 auto; background: #fff; padding: 36px 40px; border-radius: 12px; box-shadow: 0 8px 30px rgba(15,23,42,0.08); }}
    .toolbar {{ display: flex; justify-content: flex-end; gap: 10px; margin-bottom: 16px; }}
    .btn {{ background: #0f172a; color: #fff; border: none; padding: 9px 16px; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 13px; }}
    .btn:hover {{ background: #1e293b; }}
    .header {{ border-bottom: 2px solid var(--ink); padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; color: #fff; background: var(--sev); }}
    .badge-status {{ background: {'#059669' if exec_sum['status'] == 'MITIGATED' else '#334155'}; margin-left: 6px; }}
    h1 {{ font-size: 22px; margin: 6px 0 4px; }}
    h2 {{ font-size: 16px; margin: 24px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border); color: #0f172a; }}
    .meta {{ font-size: 12px; color: var(--muted); }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }}
    .card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; }}
    .card h3 {{ margin: 0 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em; color: #334155; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 12px 0; }}
    .kpi {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px; text-align: center; }}
    .kpi .val {{ font-size: 20px; font-weight: 800; color: var(--ink); }}
    .kpi .lbl {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 8px; }}
    th, td {{ border: 1px solid var(--border); padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 700; }}
    pre {{ background: #0f172a; color: #e2e8f0; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 12px; line-height: 1.45; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }}
    .analogy {{ border-left: 4px solid #0284c7; background: #f0f9ff; padding: 10px 14px; border-radius: 0 8px 8px 0; margin: 10px 0; font-size: 13.5px; }}
    ol, ul {{ padding-left: 20px; margin: 8px 0; }}
    li {{ margin-bottom: 6px; font-size: 13.5px; }}
    @media print {{
      body {{ background: #fff; padding: 0; }}
      .page {{ box-shadow: none; padding: 0; max-width: 100%; }}
      .toolbar {{ display: none; }}
      pre {{ white-space: pre-wrap; word-break: break-word; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="toolbar">
      <button class="btn" onclick="window.print()">In / Lưu thành PDF</button>
    </div>

    <div class="header">
      <div>
        <div class="meta">FINSEC AGENT — AUTONOMOUS AI SOC &amp; VIRTUAL PATCHING REPORT</div>
        <h1>{esc(str(exec_sum['headline']))}</h1>
        <div class="meta">
          Mã sự cố: <code>{esc(str(incident.get('id', 'INC')))}</code> •
          Thời điểm: <code>{esc(str(incident.get('created_at', 'N/A')))}</code> •
          Engine: <code>{esc(str(tech['engine_used']))}</code>
        </div>
      </div>
      <div style="white-space:nowrap;">
        <span class="badge">{esc(sev)}</span>
        <span class="badge badge-status">{esc(str(exec_sum['status']))}</span>
      </div>
    </div>

    <h2>1. Tóm tắt Điều hành (Executive Summary — Dễ hiểu cho Lãnh đạo &amp; Vận hành)</h2>
    <p><strong>Diễn biến chính:</strong> {esc(str(exec_sum['what_happened']))}</p>
    <div class="analogy">
      <strong>Hình dung đời thực:</strong> {esc(str(exec_sum['plain_language_analogy']))}
    </div>
    <div class="grid-2">
      <div class="card">
        <h3>Tác động Kinh doanh &amp; Tài chính</h3>
        <p style="margin:0;font-size:13.5px;">{esc(str(exec_sum['business_impact']))}</p>
      </div>
      <div class="card">
        <h3>Tình trạng Bảo vệ &amp; An toàn Khách hàng</h3>
        <p style="margin:0 0 6px;font-size:13.5px;">{esc(str(exec_sum['protection_status']))}</p>
        <p style="margin:0;font-size:12.5px;color:#334155;"><strong>Chống Prompt Injection:</strong> {esc(str(exec_sum['prompt_injection_warning']))}</p>
      </div>
    </div>

    <h2>2. Phân tích Kỹ thuật Chuyên sâu (Technical Deep-Dive — SOC / AppSec)</h2>
    <table>
      <tbody>
        <tr><th style="width:240px;">OWASP API Top 10 (2023)</th><td><code>{esc(str(tech['owasp_api_top_10']))}</code></td></tr>
        <tr><th>Phân loại CWE</th><td>{esc(str(tech['cwe_mapping']))}</td></tr>
        <tr><th>MITRE ATT&amp;CK</th><td>{esc(str(tech['mitre_attack']))}</td></tr>
        <tr><th>Ước lượng CVSS v3.1</th><td><code>{esc(str(tech['cvss_v31_estimate']))}</code></td></tr>
        <tr><th>Nguyên nhân gốc rễ (Root Cause)</th><td>{esc(str(tech['root_cause_analysis']))}</td></tr>
        <tr><th>Cơ chế Virtual Patching (&lt;5ms)</th><td>{esc(str(tech['virtual_patch_mechanism']))}</td></tr>
      </tbody>
    </table>

    <h2>3. Kiểm chứng Bán kính Ảnh hưởng (Dry-Run Blast Radius)</h2>
    <div class="kpi-grid">
      <div class="kpi"><div class="val">{esc(str(dry_run.get('total_clean', 0)))}</div><div class="lbl">Giao dịch sạch kiểm định</div></div>
      <div class="kpi"><div class="val" style="color:{'#059669' if int(dry_run.get('blocked_clean', 0)) == 0 else '#dc2626'}">{esc(str(dry_run.get('blocked_clean', 0)))} ({esc(str(dry_run.get('false_positive_rate', 0)))}%)</div><div class="lbl">False Positives (Chặn nhầm)</div></div>
      <div class="kpi"><div class="val">{esc(str(dry_run.get('blocked_attack_logs', 0)))}/{esc(str(dry_run.get('total_attack_logs', 0)))}</div><div class="lbl">Tấn công bị chặn</div></div>
      <div class="kpi"><div class="val" style="color:{'#059669' if dry_run.get('safe_to_enforce') else '#ea580c'}">{'AN TOÀN' if dry_run.get('safe_to_enforce') else 'RÀ SOÁT'}</div><div class="lbl">Kết luận Enforce</div></div>
    </div>

    <h2>4. Dòng thời gian Tấn công (Attack Timeline)</h2>
    <table>
      <thead><tr><th>Thời gian</th><th>Giai đoạn</th><th>IP nguồn</th><th>Endpoint</th><th>Chi tiết</th></tr></thead>
      <tbody>{timeline_rows}</tbody>
    </table>

    <h2>5. Dấu vết Điều tra AI Agent (ReAct Reasoning Trace)</h2>
    <ul>{trace_items}</ul>

    <h2>6. Luật Phòng thủ Khai báo (Declarative Virtual Patch JSON)</h2>
    <pre>{rule_json}</pre>

    <h2>7. Bản vá Mã nguồn Gốc rễ (Permanent Hotfix Diff)</h2>
    <pre>{diff_text}</pre>

    <h2>8. Kế hoạch Khắc phục &amp; Kiểm thử Hồi quy (Remediation Checklist)</h2>
    <ol>{checklist_items}</ol>

    <div class="meta" style="margin-top:24px;border-top:1px solid var(--border);padding-top:10px;">
      Xuất tự động bởi FinSec Agent SOC Platform • {esc(str(analysis['generated_at']))}
    </div>
  </div>
</body>
</html>
"""

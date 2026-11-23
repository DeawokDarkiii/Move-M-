-- FinSec Agent — Supabase (PostgreSQL) Schema
-- Run this script in the Supabase SQL Editor before running scripts/seed_db.py

-- 1. Ví điện tử mô phỏng
CREATE TABLE IF NOT EXISTS wallets (
  id TEXT PRIMARY KEY,              -- vd: 'W_1001'
  owner_id TEXT NOT NULL,           -- vd: 'usr_an'
  balance BIGINT NOT NULL DEFAULT 10000000
);

-- 2. Sổ cái biến động số dư (AI dùng để đối chiếu chênh lệch tiền thật)
CREATE TABLE IF NOT EXISTS ledger_entries (
  id BIGSERIAL PRIMARY KEY,
  wallet_id TEXT REFERENCES wallets(id) ON DELETE CASCADE,
  tx_ref TEXT NOT NULL,             -- Mã giao dịch / event_id từ webhook
  amount BIGINT NOT NULL,
  entry_type TEXT NOT NULL,         -- 'DEPOSIT', 'WITHDRAW', 'TRANSFER'
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ledger_wallet_id ON ledger_entries(wallet_id);
CREATE INDEX IF NOT EXISTS idx_ledger_tx_ref ON ledger_entries(tx_ref);

-- 3. Nhật ký HTTP/API đa dịch vụ
CREATE TABLE IF NOT EXISTS api_logs (
  id BIGSERIAL PRIMARY KEY,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INT NOT NULL,
  ip_address TEXT NOT NULL,
  user_agent TEXT,
  actor_id TEXT,                    -- user_id trích từ JWT (nếu có)
  api_key_id TEXT,                  -- tên internal key (nếu có)
  request_body JSONB DEFAULT '{}'::jsonb,
  is_clean_baseline BOOLEAN DEFAULT FALSE, -- TRUE = log sạch lịch sử dùng để Dry-Run
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_logs_baseline ON api_logs(is_clean_baseline);
CREATE INDEX IF NOT EXISTS idx_api_logs_created_at ON api_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_logs_path ON api_logs(path);

-- 4. Luật phòng thủ động (Virtual Patching Rules)
CREATE TABLE IF NOT EXISTS policy_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'DRAFT', -- 'DRAFT' | 'ACTIVE' | 'ROLLED_BACK'
  rule_spec JSONB NOT NULL,             -- Cấu trúc JSON khai báo an toàn (không dùng eval)
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_rules_status ON policy_rules(status);

-- 5. Hồ sơ sự cố do AI Agent điều tra
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,           -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  owasp_tag TEXT,                   -- vd: 'API1:2023 Broken Object Level Authorization'
  reasoning_trace JSONB NOT NULL,   -- Danh sách từng bước Agent gọi tool & phát hiện
  attack_timeline JSONB NOT NULL,
  proposed_rule JSONB,
  dry_run_report JSONB,             -- { total_clean: 300, blocked_clean: 0, attack_blocked: true }
  hotfix_diff TEXT,
  status TEXT DEFAULT 'OPEN',       -- 'OPEN' | 'MITIGATED'
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);

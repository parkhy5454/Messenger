CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT UNIQUE,
  password_hash TEXT,
  kakao_id TEXT UNIQUE,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  email_code TEXT,
  email_code_expires TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS status_msg TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT false;

-- 친구: status = 'pending'(요청 중) | 'accepted'(친구)
CREATE TABLE IF NOT EXISTS friendships (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, friend_id)
);
ALTER TABLE friendships ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'accepted';

-- 그룹 채팅
CREATE TABLE IF NOT EXISTS groups (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);

-- 파일 (DB에 직접 저장, 1개 최대 2MB)
CREATE TABLE IF NOT EXISTS files (
  id BIGSERIAL PRIMARY KEY,
  uploader_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INT NOT NULL,
  data BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 메시지: 1:1은 recipient_id, 그룹은 group_id 사용
CREATE TABLE IF NOT EXISTS messages (
  id BIGSERIAL PRIMARY KEY,
  sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INT REFERENCES users(id) ON DELETE CASCADE,
  group_id INT REFERENCES groups(id) ON DELETE CASCADE,
  text TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'text',
  file_id BIGINT,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 기존 DB 마이그레이션 (이미 있는 테이블용)
ALTER TABLE messages ALTER COLUMN recipient_id DROP NOT NULL;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS group_id INT REFERENCES groups(id) ON DELETE CASCADE;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'text';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_id BIGINT;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'messages' AND column_name = 'read_at') THEN
    ALTER TABLE messages ADD COLUMN read_at TIMESTAMPTZ;
    UPDATE messages SET read_at = created_at; -- 기존 메시지는 모두 읽음 처리 (최초 1회만 실행)
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS messages_dm_idx ON messages (sender_id, recipient_id, id);
CREATE INDEX IF NOT EXISTS messages_group_idx ON messages (group_id, id);

CREATE TABLE IF NOT EXISTS blocks (
  blocker_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (blocker_id, blocked_id)
);
CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY,
  reporter_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 푸시 알림 구독 (기기별 1행)
CREATE TABLE IF NOT EXISTS push_subs (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint TEXT UNIQUE NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 서버 설정값 (VAPID 키 등)
CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- 종단간 암호화: 공개키, 비밀번호로 감싼 개인키, 메시지 암호화 여부
ALTER TABLE users ADD COLUMN IF NOT EXISTS pubkey TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS enc_privkey TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS enc BOOLEAN NOT NULL DEFAULT false;

-- 그룹 E2EE: 그룹 암호화 여부, 키 세대(epoch), 나간 사람이 생겨서 키 교체가 필요한지
ALTER TABLE groups ADD COLUMN IF NOT EXISTS enc BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS epoch INT NOT NULL DEFAULT 0;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS needs_rotate BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS key_epoch INT;
-- 멤버별로 감싼 그룹 키: 보낸 사람(from_user)과의 공유 키로 감싸져 있습니다
CREATE TABLE IF NOT EXISTS group_keys (
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  epoch INT NOT NULL,
  from_user INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped TEXT NOT NULL,
  PRIMARY KEY (group_id, user_id, epoch)
);

-- 기기 간 키 승인: 새 기기 요청 (5분 후 만료, 승인 후 한 번만 전달)
CREATE TABLE IF NOT EXISTS device_requests (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pubkey TEXT NOT NULL,
  payload TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ NOT NULL
);

-- 메시지 답장·수정·삭제
ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to INT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false;

-- 읽음 표시 설정: 전체(users.receipts_on)와 대화별(chat_prefs)
ALTER TABLE users ADD COLUMN IF NOT EXISTS receipts_on BOOLEAN NOT NULL DEFAULT true;
CREATE TABLE IF NOT EXISTS chat_prefs (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INT NOT NULL,
  kind TEXT NOT NULL,
  receipts BOOLEAN NOT NULL,
  PRIMARY KEY (user_id, target_id, kind)
);

-- 프로필 공개 범위와 마지막 접속 시각
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_status_msg BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_online BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_last_seen BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;

-- 프로필 사진: 업로드한 이미지 파일 id와 공개 여부
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_file_id INT REFERENCES files(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS show_photo BOOLEAN NOT NULL DEFAULT true;

-- 사라지는 메시지 / 한 번만 보기
ALTER TABLE messages ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS view_once BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS viewed_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS conv_ttl (
  a INT NOT NULL,
  b INT NOT NULL,
  ttl INT NOT NULL,
  PRIMARY KEY (a, b)
);

-- 그룹 초대 링크 (7일 유효)
CREATE TABLE IF NOT EXISTS group_invites (
  token TEXT PRIMARY KEY,
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  created_by INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

-- 기기 관리(로그인 세션) 와 2단계 인증(TOTP)
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked BOOLEAN NOT NULL DEFAULT false
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;

-- 메시지 이모지 반응, 예약 전송
CREATE TABLE IF NOT EXISTS message_reactions (
  message_id INT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  emoji TEXT NOT NULL,
  PRIMARY KEY (message_id, user_id, emoji)
);
CREATE TABLE IF NOT EXISTS scheduled_messages (
  id SERIAL PRIMARY KEY,
  sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  send_at TIMESTAMPTZ NOT NULL
);

-- 예약 전송: 파일 첨부 지원
ALTER TABLE scheduled_messages ADD COLUMN IF NOT EXISTS file_id INT;

-- 멀티 프로필 (친구마다 보여줄 프로필 지정)
CREATE TABLE IF NOT EXISTS profiles (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status_msg TEXT NOT NULL DEFAULT '',
  avatar_file_id INT REFERENCES files(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS profile_assign (
  owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  viewer_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  profile_id INT REFERENCES profiles(id) ON DELETE SET NULL,
  PRIMARY KEY (owner_id, viewer_id)
);

-- AI 어시스턴트 대화 (평문 저장, 종단간 암호화 아님)
CREATE TABLE IF NOT EXISTS ai_messages (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ai_messages_user ON ai_messages (user_id, id);

-- 봇 계정 표시 (로그인 불가)
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;

-- 프리미엄 구독 (토스페이먼츠 빌링키 자동결제)
CREATE TABLE IF NOT EXISTS subscriptions (
  user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  customer_key TEXT NOT NULL UNIQUE,
  billing_key TEXT,
  status TEXT NOT NULL DEFAULT 'none',
  period_end TIMESTAMPTZ,
  next_billing_at TIMESTAMPTZ,
  retry_count INT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  order_id TEXT NOT NULL,
  amount INT NOT NULL,
  status TEXT NOT NULL,
  payment_key TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 방해 금지 시간 (한국 시간 기준, 푸시만 차단) 과 대화방 알림 끄기
ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_on BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_from SMALLINT NOT NULL DEFAULT 22;
ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_to SMALLINT NOT NULL DEFAULT 8;
CREATE TABLE IF NOT EXISTS muted_chats (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('dm', 'group')),
  target_id INT NOT NULL,
  PRIMARY KEY (user_id, kind, target_id)
);

-- 그룹 목적 템플릿, 공지, 일정
ALTER TABLE groups ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'general';
ALTER TABLE groups ADD COLUMN IF NOT EXISTS notice TEXT;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS notice_epoch INT;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS notice_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS group_events (
  id SERIAL PRIMARY KEY,
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  epoch INT,
  starts_at TIMESTAMPTZ NOT NULL,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS group_events_group ON group_events (group_id, starts_at);

-- 그룹 투표
CREATE TABLE IF NOT EXISTS polls (
  id SERIAL PRIMARY KEY,
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  payload TEXT NOT NULL,
  epoch INT,
  multi BOOLEAN NOT NULL DEFAULT false,
  opt_count INT NOT NULL,
  closes_at TIMESTAMPTZ NOT NULL,
  closed BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS poll_votes (
  poll_id INT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  option_idx INT NOT NULL,
  PRIMARY KEY (poll_id, user_id, option_idx)
);
CREATE INDEX IF NOT EXISTS polls_group ON polls (group_id, id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS share_token TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS discoverable BOOLEAN NOT NULL DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS users_share_token ON users (share_token) WHERE share_token IS NOT NULL;

CREATE TABLE IF NOT EXISTS status_samples (
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  ok BOOLEAN NOT NULL,
  latency_ms INT NOT NULL
);
CREATE INDEX IF NOT EXISTS status_samples_ts ON status_samples (ts);

ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_discoverable BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS users_phone_hash ON users (phone_hash);
CREATE TABLE IF NOT EXISTS phone_codes (
  user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  phone_hash TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS group_reads (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id INT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  last_msg_id BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS messages_group_id ON messages (group_id, id);

CREATE TABLE IF NOT EXISTS login_requests (
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  ua TEXT NOT NULL DEFAULT '',
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  attempts INT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TIMESTAMPTZ NOT NULL
);

-- 약관 동의 기록 (정책 버전과 동의 시각)
ALTER TABLE users ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS policy_agreed_at TIMESTAMPTZ;

-- 회원 탈퇴 시각 (탈퇴한 계정은 이름이 '탈퇴한 사용자'로 표시되고 로그인할 수 없음)
ALTER TABLE users ADD COLUMN IF NOT EXISTS withdrawn_at TIMESTAMPTZ;

-- 대화방 고정 (사용자별, 최대 20개)
CREATE TABLE IF NOT EXISTS chat_pins (
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('dm', 'group')),
  target_id INT NOT NULL,
  PRIMARY KEY (user_id, kind, target_id)
);

-- 푸시 알림 미리보기 표시 여부 (기본 켜짐)
ALTER TABLE users ADD COLUMN IF NOT EXISTS push_preview BOOLEAN NOT NULL DEFAULT true;

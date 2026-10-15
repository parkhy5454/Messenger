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

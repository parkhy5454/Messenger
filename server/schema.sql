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

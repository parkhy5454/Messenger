const http = require('http');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { pool, init } = require('./db');
const { limit } = require('./ratelimit');
const webpush = require('web-push');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET 환경 변수가 필요합니다.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1); // Render 프록시 뒤에서 실제 사용자 IP를 읽기 위함
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, '..', 'client')));

// 메일 발송: SMTP_HOST가 없으면 인증 코드를 서버 로그에만 출력합니다 (개발용).
const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_PORT === '465',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

// 우선순위: RESEND_API_KEY(HTTPS 443 포트, 막히지 않음) > SMTP_HOST > 개발용 로그 출력
async function sendCode(email, code) {
  const subject = '[Messenger] 이메일 인증 코드';
  const text = `인증 코드: ${code}\n10분 안에 입력해 주세요.`;
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;

  if (process.env.RESEND_API_KEY) {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from, to: [email], subject, text }),
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) {
      const detail = await r.text();
      throw new Error(`Resend 발송 실패 ${r.status}: ${detail}`);
    }
    return;
  }

  if (!mailer) {
    console.log(`[개발] ${email} 인증 코드: ${code}`);
    return;
  }
  await mailer.sendMail({ from, to: email, subject, text });
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
// 로그인 세션: 토큰(JWT)에 세션 id(sid)를 넣고, 세션이 취소되면 인증이 실패합니다
function deviceName(ua) {
  ua = String(ua || '');
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Macintosh/.test(ua) ? 'Mac' : /Linux/.test(ua) ? 'Linux' : '기기';
  const br = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : '브라우저';
  return br + ' · ' + os;
}
async function issueFor(u, req) {
  const s = await pool.query('INSERT INTO sessions (user_id, device) VALUES ($1,$2) RETURNING id',
    [u.id, deviceName(req && req.headers['user-agent'])]);
  return jwt.sign({ id: u.id, username: u.username, sid: s.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
}

// 2단계 인증 (TOTP, RFC 6238): 비밀키는 AES-256-GCM으로 암호화해서 저장
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) {
    val = (val << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function totpAt(secretBuf, counter) {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(counter));
  const h = require('crypto').createHmac('sha1', secretBuf).update(c).digest();
  const o = h[h.length - 1] & 15;
  const code = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000;
  return String(code).padStart(6, '0');
}
function totpCheck(secretBuf, code) {
  const t = Math.floor(Date.now() / 30000);
  return [-1, 0, 1].some((d) => totpAt(secretBuf, t + d) === String(code || '').trim());
}
const TOTP_KEY = require('crypto').createHash('sha256').update(JWT_SECRET).digest();
function encSecret(buf) {
  const iv = require('crypto').randomBytes(12);
  const c = require('crypto').createCipheriv('aes-256-gcm', TOTP_KEY, iv);
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return [iv, c.getAuthTag(), ct].map((x) => x.toString('hex')).join(':');
}
function decSecret(s) {
  const [iv, tag, ct] = String(s).split(':').map((x) => Buffer.from(x, 'hex'));
  const d = require('crypto').createDecipheriv('aes-256-gcm', TOTP_KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: '로그인이 필요합니다' });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    if (req.user.sid) {
      const r = await pool.query('SELECT 1 FROM sessions WHERE id=$1 AND user_id=$2 AND revoked=false', [req.user.sid, req.user.id]);
      if (!r.rows[0]) return res.status(401).json({ error: '로그인이 만료되었습니다' });
      pool.query('UPDATE sessions SET last_seen=now() WHERE id=$1', [req.user.sid]).catch(() => {});
    }
  } catch {
    return res.status(401).json({ error: '로그인이 만료되었습니다' });
  }
  next();
}

async function isBlocked(a, b) {
  const { rows } = await pool.query(
    'SELECT 1 FROM blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)',
    [a, b]
  );
  return rows.length > 0;
}

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;

// ---- 인증 ----
app.post('/api/auth/signup', limit({ windowMs: 10 * 60 * 1000, max: 5 }), wrap(async (req, res) => {
  const { username, password, name, email } = req.body || {};
  const uname = String(username || '').toLowerCase();
  if (!USERNAME_RE.test(uname)) return res.status(400).json({ error: '아이디는 영소문자·숫자·_ 조합 3~20자입니다' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: '비밀번호는 8자 이상이어야 합니다' });
  if (!name || !email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: '이름과 올바른 이메일을 입력하세요' });

  const dup = await pool.query(
    'SELECT 1 FROM users WHERE username=$1 OR email=$2 LIMIT 1',
    [uname, email.toLowerCase()]
  );
  if (dup.rows.length) return res.status(409).json({ error: '이미 사용 중인 아이디 또는 이메일입니다' });

  const hash = await bcrypt.hash(password, 10);
  const code = String(crypto.randomInt(100000, 1000000));

  // 메일이 성공적으로 나간 뒤에만 계정을 저장합니다 (실패 시 미인증 계정이 남지 않음)
  try {
    await sendCode(email, code);
  } catch (e) {
    console.error('인증 메일 발송 실패:', e.message);
    return res.status(502).json({ error: '인증 메일 발송에 실패했습니다. 잠시 후 다시 시도해 주세요' });
  }

  try {
    await pool.query(
      `INSERT INTO users (username, name, email, password_hash, email_verified, email_code, email_code_expires)
       VALUES ($1, $2, $3, $4, false, $5, now() + interval '10 minutes')`,
      [uname, name.trim(), email.toLowerCase(), hash, sha256(code)]
    );
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: '이미 사용 중인 아이디 또는 이메일입니다' });
    throw e;
  }
  res.status(201).json({ ok: true });
}));

// 인증 코드 무차별 대입 방지: 이메일당 10분에 10회까지만 확인 허용
app.post('/api/auth/verify', limit({ windowMs: 10 * 60 * 1000, max: 10, key: (req) => 'verify:' + String((req.body || {}).email || '').toLowerCase() }), wrap(async (req, res) => {
  const { email, code } = req.body || {};
  const { rows } = await pool.query(
    `UPDATE users SET email_verified=true, email_code=NULL
     WHERE email=$1 AND email_code=$2 AND email_code_expires > now()
     RETURNING id`,
    [String(email || '').toLowerCase(), sha256(String(code || ''))]
  );
  if (!rows[0]) return res.status(400).json({ error: '코드가 틀렸거나 만료되었습니다' });
  res.json({ ok: true });
}));

app.post('/api/auth/login', limit({ windowMs: 15 * 60 * 1000, max: 20, key: (req) => 'login:' + req.ip + ':' + String((req.body || {}).username || '').toLowerCase() }), wrap(async (req, res) => {
  const { username, password } = req.body || {};
  const { rows } = await pool.query(
    'SELECT id, username, password_hash, email_verified, banned, totp_enabled FROM users WHERE username=$1',
    [String(username || '').toLowerCase()]
  );
  const u = rows[0];
  if (!u || !u.password_hash || !(await bcrypt.compare(String(password || ''), u.password_hash))) {
    return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다' });
  }
  if (!u.email_verified) return res.status(403).json({ error: '이메일 인증을 먼저 완료하세요' });
  if (u.banned) return res.status(403).json({ error: '이용이 제한된 계정입니다' });
  if (u.totp_enabled) {
    return res.json({ otp: true, pending: jwt.sign({ id: u.id, purpose: 'otp' }, JWT_SECRET, { expiresIn: '5m' }) });
  }
  res.json({ token: (await issueFor(u, req)) });
}));

// 카카오 로그인 (KAKAO_REST_KEY, KAKAO_REDIRECT_URI 설정 후 동작)
app.get('/api/auth/kakao', (req, res) => {
  if (!process.env.KAKAO_REST_KEY) return res.status(501).send('카카오 로그인이 설정되지 않았습니다.');
  const url = 'https://kauth.kakao.com/oauth/authorize?' + new URLSearchParams({
    client_id: process.env.KAKAO_REST_KEY,
    redirect_uri: process.env.KAKAO_REDIRECT_URI,
    response_type: 'code',
    scope: 'account_email profile_nickname',
  });
  res.redirect(url);
});

app.get('/api/auth/kakao/callback', wrap(async (req, res) => {
  if (!req.query.code) return res.status(400).send('인증 코드가 없습니다.');
  const tr = await fetch('https://kauth.kakao.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: process.env.KAKAO_REST_KEY,
      redirect_uri: process.env.KAKAO_REDIRECT_URI,
      code: String(req.query.code),
    }),
  });
  const tok = await tr.json();
  if (!tok.access_token) return res.status(400).send('카카오 인증에 실패했습니다.');

  const me = await (await fetch('https://kapi.kakao.com/v2/user/me', {
    headers: { Authorization: 'Bearer ' + tok.access_token },
  })).json();
  const kid = String(me.id);
  const account = me.kakao_account || {};
  const nick = (account.profile && account.profile.nickname) || '카카오 사용자';
  const email = account.email && account.email_is_verified ? account.email.toLowerCase() : null;

  let { rows } = await pool.query('SELECT id, username FROM users WHERE kakao_id=$1', [kid]);
  let u = rows[0];
  if (!u) {
    try {
      ({ rows } = await pool.query(
        `INSERT INTO users (username, name, email, kakao_id, email_verified)
         VALUES ($1, $2, $3, $4, true) RETURNING id, username`,
        ['k' + kid, nick, email, kid]
      ));
    } catch (e) {
      if (e.code === '23505') return res.status(409).send('이미 같은 이메일로 가입된 계정이 있습니다.');
      throw e;
    }
    u = rows[0];
  }
  res.redirect('/#token=' + (await issueFor(u, req)));
}));

// ---- 비밀번호 찾기 / 변경 ----
// 1) 비밀번호 찾기: 이메일로 인증 코드 발송 (가입 여부는 노출하지 않음)
app.post('/api/auth/forgot', limit({ windowMs: 15 * 60 * 1000, max: 5, key: (req) => 'forgot:' + String((req.body || {}).email || '').toLowerCase() }), wrap(async (req, res) => {
  const email = String((req.body || {}).email || '').toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: '올바른 이메일을 입력하세요' });

  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1 AND email_verified', [email]);
  if (rows[0]) {
    const code = String(crypto.randomInt(100000, 1000000));
    await pool.query(
      `UPDATE users SET email_code=$2, email_code_expires=now() + interval '10 minutes' WHERE id=$1`,
      [rows[0].id, sha256(code)]
    );
    try {
      await sendCode(email, code);
    } catch (e) {
      console.error('비밀번호 찾기 메일 발송 실패:', e.message);
      return res.status(502).json({ error: '인증 메일 발송에 실패했습니다. 잠시 후 다시 시도해 주세요' });
    }
  }
  res.json({ ok: true, message: '가입된 이메일이면 인증 코드를 보냈습니다' });
}));

// 2) 인증 코드로 새 비밀번호 설정
app.post('/api/auth/reset', limit({ windowMs: 10 * 60 * 1000, max: 10, key: (req) => 'reset:' + String((req.body || {}).email || '').toLowerCase() }), wrap(async (req, res) => {
  const { email, code, password } = req.body || {};
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: '비밀번호는 8자 이상이어야 합니다' });
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    `UPDATE users SET password_hash=$3, email_code=NULL, pubkey=NULL, enc_privkey=NULL
     WHERE email=$1 AND email_code=$2 AND email_code_expires > now()
     RETURNING id`,
    [String(email || '').toLowerCase(), sha256(String(code || '')), hash]
  );
  if (!rows[0]) return res.status(400).json({ error: '코드가 틀렸거나 만료되었습니다' });
  res.json({ ok: true });
}));

// 3) 로그인 상태에서 비밀번호 변경 (현재 비밀번호 확인 필요)
app.post('/api/me/password', auth, wrap(async (req, res) => {
  const { current, next } = req.body || {};
  if (typeof next !== 'string' || next.length < 8) return res.status(400).json({ error: '새 비밀번호는 8자 이상이어야 합니다' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
  const u = rows[0];
  if (!u || !u.password_hash || !(await bcrypt.compare(String(current || ''), u.password_hash))) {
    return res.status(401).json({ error: '현재 비밀번호가 틀렸습니다' });
  }
  const hash = await bcrypt.hash(next, 10);
  const encPrivkey = typeof (req.body || {}).encPrivkey === 'string' ? req.body.encPrivkey : null;
  if (encPrivkey) {
    await pool.query('UPDATE users SET password_hash=$2, enc_privkey=$3 WHERE id=$1', [req.user.id, hash, encPrivkey]);
  } else {
    await pool.query('UPDATE users SET password_hash=$2 WHERE id=$1', [req.user.id, hash]);
  }
  res.json({ ok: true });
}));

// ---- 사용자·친구 ----
app.get('/api/me', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, username, name, status_msg, is_admin, banned, receipts_on, show_status_msg, show_online, show_last_seen, show_photo, (avatar_file_id IS NOT NULL AND show_photo) AS has_photo, totp_enabled FROM users WHERE id=$1',
    [req.user.id]
  );
  const u = rows[0];
  if (!u) return res.status(401).json({ error: '로그인이 필요합니다' });
  if (u.banned) return res.status(403).json({ error: '이용이 제한된 계정입니다' });
  res.json(u);
}));

// 프로필 수정 (이름, 상태 메시지)
app.patch('/api/me', auth, wrap(async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  const statusMsg = String((req.body || {}).statusMsg || '').trim();
  if (!name || name.length > 20) return res.status(400).json({ error: '이름은 1~20자로 입력하세요' });
  if (statusMsg.length > 60) return res.status(400).json({ error: '상태 메시지는 60자 이내로 입력하세요' });
  await pool.query('UPDATE users SET name=$2, status_msg=$3 WHERE id=$1', [req.user.id, name, statusMsg]);
  res.json({ ok: true });
}));

// ---- E2EE (1:1 종단간 암호화) 공개키 / 감싼 개인키 ----
app.get('/api/e2ee/me', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT pubkey, enc_privkey FROM users WHERE id=$1', [req.user.id]);
  if (!rows[0]) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
  res.json({ pubkey: rows[0].pubkey, enc_privkey: rows[0].enc_privkey });
}));

// 최초 키 생성 시에만 저장 (이미 있으면 덮어쓰지 않음)
app.post('/api/e2ee/setup', auth, wrap(async (req, res) => {
  const b = req.body || {};
  const pubkey = String(b.pubkey || '');
  const encPrivkey = b.encPrivkey ? String(b.encPrivkey) : null;
  if (!pubkey || pubkey.length > 500) return res.status(400).json({ error: '잘못된 공개키입니다' });
  if (encPrivkey && encPrivkey.length > 4000) return res.status(400).json({ error: '잘못된 키 데이터입니다' });
  const r = await pool.query(
    'UPDATE users SET pubkey=$2, enc_privkey=$3 WHERE id=$1 AND pubkey IS NULL',
    [req.user.id, pubkey, encPrivkey]
  );
  if (!r.rowCount) return res.status(409).json({ error: '이미 암호화 키가 설정되어 있습니다' });
  res.json({ ok: true });
}));

// 상대의 공개키 (본인 또는 수락된 친구만)
app.get('/api/users/:id/pubkey', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (id !== req.user.id) {
    const f = await pool.query(
      "SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'", [req.user.id, id]);
    if (!f.rows[0]) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
  }
  const { rows } = await pool.query('SELECT pubkey FROM users WHERE id=$1', [id]);
  if (!rows[0]) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
  res.json({ pubkey: rows[0].pubkey });
}));

// ---- 기기 간 키 승인 (새 기기는 이미 로그인된 기기의 승인으로 개인키를 받음) ----
app.post('/api/devices/request', auth, wrap(async (req, res) => {
  const pubkey = String((req.body || {}).pubkey || '');
  if (!pubkey || pubkey.length > 500) return res.status(400).json({ error: '잘못된 요청입니다' });
  await pool.query("DELETE FROM device_requests WHERE expires_at < now() - interval '1 day'");
  const { rows } = await pool.query(
    "INSERT INTO device_requests (user_id, pubkey, expires_at) VALUES ($1,$2, now() + interval '5 minutes') RETURNING id",
    [req.user.id, pubkey]);
  io.to('user:' + req.user.id).emit('device:request', { id: rows[0].id, pubkey });
  res.status(201).json({ id: rows[0].id });
}));

app.get('/api/devices/request/:id', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT status, payload, expires_at < now() AS expired FROM device_requests WHERE id=$1 AND user_id=$2',
    [Number(req.params.id), req.user.id]);
  const r = rows[0];
  if (!r) return res.status(404).json({ error: '요청을 찾을 수 없습니다' });
  if (r.status === 'pending' && r.expired) return res.json({ status: 'expired' });
  if (r.status === 'approved') {
    await pool.query("UPDATE device_requests SET status='done', payload=NULL WHERE id=$1", [Number(req.params.id)]);
    return res.json({ status: 'approved', payload: r.payload });
  }
  res.json({ status: r.status });
}));

app.post('/api/devices/request/:id/approve', auth, wrap(async (req, res) => {
  const payload = String((req.body || {}).payload || '');
  if (!payload || payload.length > 4000) return res.status(400).json({ error: '잘못된 요청입니다' });
  const r = await pool.query(
    "UPDATE device_requests SET status='approved', payload=$3 WHERE id=$1 AND user_id=$2 AND status='pending' AND expires_at > now()",
    [Number(req.params.id), req.user.id, payload]);
  if (!r.rowCount) return res.status(409).json({ error: '승인할 수 없는 요청입니다 (만료되었거나 이미 처리됨)' });
  res.json({ ok: true });
}));

app.post('/api/devices/request/:id/deny', auth, wrap(async (req, res) => {
  await pool.query("UPDATE device_requests SET status='denied' WHERE id=$1 AND user_id=$2 AND status='pending'",
    [Number(req.params.id), req.user.id]);
  res.json({ ok: true });
}));

// ---- 읽음 표시 설정 ----
app.get('/api/prefs/dm/:id', auth, wrap(async (req, res) => {
  const r = await pool.query(
    "SELECT receipts FROM chat_prefs WHERE user_id=$1 AND target_id=$2 AND kind='dm'", [req.user.id, Number(req.params.id)]);
  const g = await pool.query('SELECT receipts_on FROM users WHERE id=$1', [req.user.id]);
  res.json({ receipts: r.rows[0] ? r.rows[0].receipts : (g.rows[0] ? g.rows[0].receipts_on : true) });
}));

app.post('/api/prefs/dm/:id', auth, wrap(async (req, res) => {
  await pool.query(
    "INSERT INTO chat_prefs (user_id, target_id, kind, receipts) VALUES ($1,$2,'dm',$3) " +
    'ON CONFLICT (user_id, target_id, kind) DO UPDATE SET receipts = EXCLUDED.receipts',
    [req.user.id, Number(req.params.id), !!(req.body || {}).receipts]);
  res.json({ ok: true });
}));

app.post('/api/prefs/receipts', auth, wrap(async (req, res) => {
  await pool.query('UPDATE users SET receipts_on=$2 WHERE id=$1', [req.user.id, !!(req.body || {}).receiptsOn]);
  res.json({ ok: true });
}));

// 프로필 공개 설정 (상태 메시지, 온라인 표시, 마지막 접속)
app.post('/api/prefs/profile', auth, wrap(async (req, res) => {
  const b = req.body || {};
  const cols = { showStatus: 'show_status_msg', showOnline: 'show_online', showLastSeen: 'show_last_seen', showPhoto: 'show_photo' };
  const sets = [];
  const vals = [req.user.id];
  for (const k of Object.keys(cols)) {
    if (typeof b[k] === 'boolean') { vals.push(b[k]); sets.push(cols[k] + '=$' + vals.length); }
  }
  if (sets.length) await pool.query('UPDATE users SET ' + sets.join(', ') + ' WHERE id=$1', vals);
  res.json({ ok: true });
}));

// ---- 프로필 사진 ----
// 내 사진 지정 (먼저 /api/files 로 올린 이미지 id)
app.post('/api/me/avatar', auth, wrap(async (req, res) => {
  const fileId = Number((req.body || {}).fileId);
  const f = await pool.query('SELECT mime FROM files WHERE id=$1 AND uploader_id=$2', [fileId, req.user.id]);
  if (!f.rows[0] || !String(f.rows[0].mime).startsWith('image/')) return res.status(400).json({ error: '사진 파일을 선택하세요' });
  await pool.query('UPDATE users SET avatar_file_id=$2 WHERE id=$1', [req.user.id, fileId]);
  res.json({ ok: true });
}));

// 사진 보기: 본인, 또는 수락된 친구이면서 상대가 사진 공개를 켠 경우만
app.get('/api/users/:id/avatar', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query(
    'SELECT u.avatar_file_id, u.show_photo, f.mime, f.data FROM users u LEFT JOIN files f ON f.id = u.avatar_file_id WHERE u.id=$1',
    [id]);
  const r = rows[0];
  if (!r || !r.avatar_file_id) return res.status(404).end();
  if (id !== req.user.id) {
    const fr = await pool.query("SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'", [req.user.id, id]);
    if (!fr.rows[0] || !r.show_photo) return res.status(404).end();
  }
  res.set('Content-Type', r.mime);
  res.set('Cache-Control', 'private, max-age=300');
  res.send(r.data);
}));

// ---- 사라지는 메시지 설정 (1:1 대화, 양쪽 모두에 적용) ----
app.post('/api/prefs/ttl/:id', auth, wrap(async (req, res) => {
  const other = Number(req.params.id);
  const f = await pool.query("SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'", [req.user.id, other]);
  if (!f.rows[0]) return res.status(404).json({ error: '친구와의 대화에서만 설정할 수 있습니다' });
  const ttl = Math.max(0, Math.min(604800, Number((req.body || {}).ttl) || 0));
  const a = Math.min(req.user.id, other), b = Math.max(req.user.id, other);
  if (!ttl) await pool.query('DELETE FROM conv_ttl WHERE a=$1 AND b=$2', [a, b]);
  else await pool.query('INSERT INTO conv_ttl (a, b, ttl) VALUES ($1,$2,$3) ON CONFLICT (a, b) DO UPDATE SET ttl = EXCLUDED.ttl', [a, b, ttl]);
  res.json({ ok: true, ttl });
}));

// ---- 한 번만 보기: 받는 사람이 열면 사진 데이터를 지우고 양쪽에 알림 ----
app.post('/api/messages/:id/view', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query(
    'SELECT sender_id, recipient_id, file_id FROM messages WHERE id=$1 AND recipient_id=$2 AND view_once=true AND viewed_at IS NULL AND deleted=false',
    [id, req.user.id]);
  const m = rows[0];
  if (!m) return res.status(404).json({ error: '열 수 없는 메시지입니다' });
  await pool.query('UPDATE messages SET viewed_at=now(), file_id=NULL WHERE id=$1', [id]);
  if (m.file_id) await pool.query('DELETE FROM files WHERE id=$1', [m.file_id]);
  io.to(['user:' + m.sender_id, 'user:' + m.recipient_id]).emit('message:viewed', { id });
  res.json({ ok: true });
}));

// ---- 그룹 초대 링크 ----
// 멤버가 링크를 만듭니다 (7일 유효). 암호화 그룹이면 새 멤버의 키는 기존 멤버가 그룹을 열 때 전달됩니다.
app.post('/api/groups/:id/invite', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, req.user.id))) return res.status(403).json({ error: '그룹 멤버만 초대 링크를 만들 수 있습니다' });
  const token = require('crypto').randomBytes(16).toString('hex');
  await pool.query(
    "INSERT INTO group_invites (token, group_id, created_by, expires_at) VALUES ($1,$2,$3, now() + interval '7 days')",
    [token, groupId, req.user.id]);
  res.status(201).json({ token });
}));

// 초대 링크 정보 (그룹 이름, 인원)
app.get('/api/invites/:token', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT g.id, g.name, (SELECT COUNT(*)::int FROM group_members gm WHERE gm.group_id = g.id) AS members
     FROM group_invites i JOIN groups g ON g.id = i.group_id
     WHERE i.token=$1 AND i.expires_at > now()`,
    [String(req.params.token)]);
  if (!rows[0]) return res.status(404).json({ error: '만료되었거나 잘못된 초대 링크입니다' });
  res.json(rows[0]);
}));

// 초대 링크로 참여 (최대 50명)
app.post('/api/invites/:token/join', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT i.group_id, (SELECT COUNT(*)::int FROM group_members gm WHERE gm.group_id = i.group_id) AS members FROM group_invites i WHERE i.token=$1 AND i.expires_at > now()',
    [String(req.params.token)]);
  if (!rows[0]) return res.status(404).json({ error: '만료되었거나 잘못된 초대 링크입니다' });
  if (rows[0].members >= 50) return res.status(400).json({ error: '그룹 인원이 가득 찼습니다' });
  await pool.query('INSERT INTO group_members (group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [rows[0].group_id, req.user.id]);
  res.json({ id: rows[0].group_id });
}));

// ---- 2단계 인증 설정 ----
app.post('/api/2fa/setup', auth, wrap(async (req, res) => {
  const secret = require('crypto').randomBytes(20);
  await pool.query('UPDATE users SET totp_secret=$2, totp_enabled=false WHERE id=$1', [req.user.id, encSecret(secret)]);
  // 인증 앱에서 스캔할 QR 코드 (otpauth 주소를 PNG 데이터 URL로)
  const u = await pool.query('SELECT username FROM users WHERE id=$1', [req.user.id]);
  const key = b32encode(secret);
  const uri = 'otpauth://totp/' + encodeURIComponent('Messenger:' + u.rows[0].username) + '?secret=' + key + '&issuer=Messenger';
  const qr = await require('qrcode').toDataURL(uri, { margin: 1, width: 220 });
  res.json({ secret: key, qr });
}));
app.post('/api/2fa/enable', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT totp_secret FROM users WHERE id=$1', [req.user.id]);
  if (!rows[0] || !rows[0].totp_secret) return res.status(400).json({ error: '먼저 2단계 인증 설정을 시작하세요' });
  if (!totpCheck(decSecret(rows[0].totp_secret), (req.body || {}).code)) return res.status(400).json({ error: '인증 코드가 올바르지 않습니다' });
  await pool.query('UPDATE users SET totp_enabled=true WHERE id=$1', [req.user.id]);
  res.json({ ok: true });
}));
app.post('/api/2fa/disable', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.user.id]);
  if (!rows[0] || !(await bcrypt.compare(String((req.body || {}).password || ''), rows[0].password_hash || ''))) {
    return res.status(400).json({ error: '비밀번호가 올바르지 않습니다' });
  }
  await pool.query('UPDATE users SET totp_enabled=false, totp_secret=NULL WHERE id=$1', [req.user.id]);
  res.json({ ok: true });
}));

// 로그인 2단계: 비밀번호가 맞으면 임시 토큰을 주고, 인증 코드를 확인해서 로그인 토큰을 줍니다
app.post('/api/auth/otp', limit({ windowMs: 10 * 60 * 1000, max: 10, key: (req) => 'otp:' + req.ip }), wrap(async (req, res) => {
  let p;
  try {
    p = jwt.verify(String((req.body || {}).pending || ''), JWT_SECRET);
  } catch {
    return res.status(401).json({ error: '인증 시간이 지났습니다. 다시 로그인하세요' });
  }
  if (p.purpose !== 'otp') return res.status(401).json({ error: '잘못된 요청입니다' });
  const { rows } = await pool.query('SELECT id, username, totp_secret, banned FROM users WHERE id=$1 AND totp_enabled=true', [p.id]);
  const u = rows[0];
  if (!u || u.banned || !totpCheck(decSecret(u.totp_secret), (req.body || {}).code)) {
    return res.status(401).json({ error: '인증 코드가 올바르지 않습니다' });
  }
  res.json({ token: await issueFor(u, req) });
}));

// ---- 기기 관리 ----
app.get('/api/sessions', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, device, created_at, last_seen FROM sessions WHERE user_id=$1 AND revoked=false ORDER BY last_seen DESC',
    [req.user.id]);
  res.json(rows.map((r) => ({ ...r, current: r.id === req.user.sid })));
}));
app.delete('/api/sessions/:id', auth, wrap(async (req, res) => {
  await pool.query('UPDATE sessions SET revoked=true WHERE id=$1 AND user_id=$2', [Number(req.params.id), req.user.id]);
  res.json({ ok: true });
}));
app.post('/api/sessions/revoke-others', auth, wrap(async (req, res) => {
  await pool.query('UPDATE sessions SET revoked=true WHERE user_id=$1 AND id<>$2', [req.user.id, req.user.sid || 0]);
  res.json({ ok: true });
}));

// ---- 예약 전송 (1:1, 지금부터 30일 이내) ----
app.post('/api/scheduled', auth, wrap(async (req, res) => {
  const b = req.body || {};
  const to = Number(b.to);
  const text = String(b.text || '');
  const at = new Date(b.sendAt);
  if (!to || !text || text.length > 20000) return res.status(400).json({ error: '내용을 확인하세요' });
  if (isNaN(at) || at <= new Date() || at - new Date() > 30 * 24 * 3600 * 1000) {
    return res.status(400).json({ error: '예약 시간은 지금부터 30일 이내여야 합니다' });
  }
  const f = await pool.query("SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'", [req.user.id, to]);
  if (!f.rows[0]) return res.status(400).json({ error: '친구에게만 예약할 수 있습니다' });
  const fileId = b.fileId ? Number(b.fileId) : null;
  if (fileId) {
    const fr = await pool.query('SELECT 1 FROM files WHERE id=$1 AND uploader_id=$2', [fileId, req.user.id]);
    if (!fr.rows[0]) return res.status(400).json({ error: '파일을 찾을 수 없습니다' });
  }
  await pool.query('INSERT INTO scheduled_messages (sender_id, recipient_id, text, send_at, file_id) VALUES ($1,$2,$3,$4,$5)', [req.user.id, to, text, at, fileId]);
  res.status(201).json({ ok: true });
}));

// ---- 예약 목록 / 취소 ----
app.get('/api/scheduled', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT s.id, s.recipient_id, s.send_at, s.file_id, u.name AS recipient_name FROM scheduled_messages s JOIN users u ON u.id = s.recipient_id WHERE s.sender_id=$1 ORDER BY s.send_at',
    [req.user.id]);
  res.json(rows);
}));
app.delete('/api/scheduled/:id', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('DELETE FROM scheduled_messages WHERE id=$1 AND sender_id=$2 RETURNING file_id', [Number(req.params.id), req.user.id]);
  if (!rows[0]) return res.status(404).json({ error: '예약 메시지를 찾을 수 없습니다' });
  if (rows[0].file_id) await pool.query('DELETE FROM files WHERE id=$1', [rows[0].file_id]);
  res.json({ ok: true });
}));

app.get('/api/blocks', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.name FROM blocks b JOIN users u ON u.id = b.blocked_id WHERE b.blocker_id=$1 ORDER BY u.name`,
    [req.user.id]
  );
  res.json(rows);
}));
app.delete('/api/blocks/:userId', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM blocks WHERE blocker_id=$1 AND blocked_id=$2', [req.user.id, Number(req.params.userId)]);
  res.json({ ok: true });
}));

app.post('/api/friends', auth, wrap(async (req, res) => {
  const uname = String((req.body || {}).username || '').toLowerCase();
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1 AND email_verified', [uname]);
  const f = rows[0];
  if (!f) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
  if (f.id === req.user.id) return res.status(400).json({ error: '자기 자신은 추가할 수 없습니다' });
  if (await isBlocked(req.user.id, f.id)) return res.status(403).json({ error: '차단 관계라 추가할 수 없습니다' });

  const existing = await pool.query(
    'SELECT user_id, status FROM friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)',
    [req.user.id, f.id]
  );
  const mine = existing.rows.find((r) => r.user_id === req.user.id);
  const theirs = existing.rows.find((r) => r.user_id === f.id);
  if (mine && mine.status === 'accepted') return res.status(409).json({ error: '이미 친구입니다' });
  if (mine && mine.status === 'pending') return res.status(409).json({ error: '이미 친구 요청을 보냈습니다' });
  // 상대가 먼저 요청해 둔 경우 바로 수락 처리
  if (theirs && theirs.status === 'pending') {
    await acceptFriend(f.id, req.user.id);
    return res.status(201).json({ ok: true, status: 'accepted' });
  }

  await pool.query(
    `INSERT INTO friendships (user_id, friend_id, status) VALUES ($1,$2,'pending')
     ON CONFLICT (user_id, friend_id) DO NOTHING`,
    [req.user.id, f.id]
  );
  res.status(201).json({ ok: true, status: 'pending' });
}));

// requester → me 요청을 수락: 양쪽 모두 accepted 로 만든다
async function acceptFriend(requesterId, myId) {
  await pool.query(
    `UPDATE friendships SET status='accepted' WHERE user_id=$1 AND friend_id=$2`,
    [requesterId, myId]
  );
  await pool.query(
    `INSERT INTO friendships (user_id, friend_id, status) VALUES ($1,$2,'accepted')
     ON CONFLICT (user_id, friend_id) DO UPDATE SET status='accepted'`,
    [myId, requesterId]
  );
}

app.get('/api/friends', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.name, u.show_online, u.last_seen, u.show_photo, u.avatar_file_id,
       (CASE WHEN u.show_status_msg THEN u.status_msg ELSE NULL END) AS status_msg,
       (CASE WHEN u.show_last_seen THEN u.last_seen ELSE NULL END) AS last_seen
     FROM friendships f
     JOIN users u ON u.id = f.friend_id
     WHERE f.user_id=$1 AND f.status='accepted' ORDER BY u.name`,
    [req.user.id]
  );
  // 온라인 표시: 공개 설정이 켜져 있고 지금 접속 중일 때만
  res.json(rows.map((r) => ({
    id: r.id, username: r.username, name: r.name, status_msg: r.status_msg, last_seen: r.last_seen,
    has_photo: !!(r.show_photo && r.avatar_file_id),
    online: !!(r.show_online && io.sockets.adapter.rooms.get('user:' + r.id)),
  })));
}));

// 대화 목록: 친구별 1:1 대화와 그룹 대화의 마지막 메시지, 안 읽은 개수
app.get('/api/chats', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `WITH dm AS (
       SELECT 'dm'::text AS type, f.friend_id AS id, u.name, u.username, 0 AS members,
         (SELECT json_build_object('text', m.text, 'kind', m.kind, 'enc', m.enc, 'file_id', m.file_id, 'created_at', m.created_at)
            FROM messages m
            WHERE (m.sender_id=$1 AND m.recipient_id=f.friend_id) OR (m.sender_id=f.friend_id AND m.recipient_id=$1)
            ORDER BY m.id DESC LIMIT 1) AS last,
         (SELECT COUNT(*)::int FROM messages m
            WHERE m.sender_id=f.friend_id AND m.recipient_id=$1 AND m.read_at IS NULL) AS unread
       FROM friendships f JOIN users u ON u.id = f.friend_id
       WHERE f.user_id=$1 AND f.status='accepted'
     ),
     grp AS (
       SELECT 'group'::text AS type, g.id, g.name, ''::text AS username,
         (SELECT COUNT(*)::int FROM group_members x WHERE x.group_id = g.id) AS members,
         (SELECT json_build_object('text', m.text, 'kind', m.kind, 'created_at', m.created_at, 'sender_name', su.name, 'enc', m.enc, 'key_epoch', m.key_epoch, 'file_id', m.file_id)
            FROM messages m JOIN users su ON su.id = m.sender_id
            WHERE m.group_id = g.id ORDER BY m.id DESC LIMIT 1) AS last,
         0 AS unread
       FROM groups g JOIN group_members gm ON gm.group_id = g.id AND gm.user_id = $1
     )
     SELECT * FROM dm UNION ALL SELECT * FROM grp`,
    [req.user.id]
  );
  res.json(rows);
}));

// 나에게 온 친구 요청 목록
app.get('/api/friends/requests', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.name FROM friendships f
     JOIN users u ON u.id = f.user_id
     WHERE f.friend_id=$1 AND f.status='pending' ORDER BY f.created_at`,
    [req.user.id]
  );
  res.json(rows);
}));

// 친구 요청 수락
app.post('/api/friends/accept', auth, wrap(async (req, res) => {
  const requesterId = Number((req.body || {}).userId);
  const { rows } = await pool.query(
    `SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='pending'`,
    [requesterId, req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: '친구 요청을 찾을 수 없습니다' });
  await acceptFriend(requesterId, req.user.id);
  res.json({ ok: true });
}));

// 친구 요청 거절 (요청 기록 삭제)
app.post('/api/friends/decline', auth, wrap(async (req, res) => {
  const requesterId = Number((req.body || {}).userId);
  await pool.query(
    `DELETE FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='pending'`,
    [requesterId, req.user.id]
  );
  res.json({ ok: true });
}));

app.post('/api/blocks', auth, wrap(async (req, res) => {
  const other = Number((req.body || {}).userId);
  if (!other || other === req.user.id) return res.status(400).json({ error: '잘못된 요청입니다' });
  await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, other]);
  await pool.query('DELETE FROM friendships WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)', [req.user.id, other]);
  res.status(201).json({ ok: true });
}));

app.post('/api/reports', auth, wrap(async (req, res) => {
  const { userId, reason } = req.body || {};
  const text = String(reason || '').trim();
  if (!Number(userId) || !text || text.length > 500) return res.status(400).json({ error: '신고 사유를 500자 이내로 입력하세요' });
  await pool.query('INSERT INTO reports (reporter_id, target_id, reason) VALUES ($1,$2,$3)', [req.user.id, Number(userId), text]);
  res.status(201).json({ ok: true });
}));

// ---- 1:1 메시지 기록 ----
// before 파라미터로 이전 메시지를 50개씩 불러옵니다
app.get('/api/messages/:userId', auth, wrap(async (req, res) => {
  const other = Number(req.params.userId);
  const me = req.user.id;
  const before = Number(req.query.before) || Number.MAX_SAFE_INTEGER;
  const { rows } = await pool.query(
    `SELECT id, sender_id, recipient_id, text, kind, file_id, (CASE WHEN COALESCE((SELECT receipts FROM chat_prefs WHERE user_id=messages.recipient_id AND target_id=messages.sender_id AND kind='dm'), (SELECT receipts_on FROM users WHERE id=messages.recipient_id), true) THEN messages.read_at END) AS read_at, created_at, enc, reply_to, edited_at, deleted, view_once, viewed_at,
       (SELECT json_agg(json_build_object('emoji', r.emoji, 'user', r.user_id)) FROM message_reactions r WHERE r.message_id = messages.id) AS reactions,
       (SELECT name FROM files WHERE id = messages.file_id) AS file_name
     FROM messages
     WHERE ((sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)) AND id < $3
       AND (expires_at IS NULL OR expires_at > now())
     ORDER BY id DESC LIMIT 50`,
    [me, other, before]
  );
  res.json(rows.reverse());
}));

// 안 읽은 1:1 메시지 개수 (보낸 사람별)
app.get('/api/unread', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT sender_id, COUNT(*)::int AS count FROM messages
     WHERE recipient_id=$1 AND read_at IS NULL GROUP BY sender_id`,
    [req.user.id]
  );
  res.json(rows);
}));

// ---- 그룹 채팅 ----
async function isGroupMember(groupId, userId) {
  const { rows } = await pool.query('SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, userId]);
  return rows.length > 0;
}

app.post('/api/groups', auth, wrap(async (req, res) => {
  const name = String((req.body || {}).name || '').trim();
  const memberIds = Array.isArray((req.body || {}).memberIds) ? req.body.memberIds.map(Number) : [];
  if (!name || name.length > 30) return res.status(400).json({ error: '그룹 이름은 1~30자로 입력하세요' });
  // 멤버는 나와 친구인 사람만 가능 (최대 49명)
  const friends = await pool.query(
    `SELECT friend_id FROM friendships WHERE user_id=$1 AND status='accepted' AND friend_id = ANY($2::int[])`,
    [req.user.id, memberIds]
  );
  const ids = [...new Set(friends.rows.map((r) => r.friend_id))].slice(0, 49);
  if (!ids.length) return res.status(400).json({ error: '그룹에 초대할 친구를 선택하세요' });

  const wantEnc = !!(req.body || {}).enc;
  const keyList = Array.isArray((req.body || {}).keys) ? req.body.keys : [];
  const all = [req.user.id, ...ids];
  if (wantEnc) {
    const complete = all.every((uid) => keyList.some((k) => Number(k.userId) === uid && typeof k.wrapped === 'string' && k.wrapped.length > 0 && k.wrapped.length <= 4000));
    if (!complete) return res.status(400).json({ error: '모든 멤버의 암호화 키가 필요합니다' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const g = await client.query('INSERT INTO groups (name, owner_id, enc) VALUES ($1,$2,$3) RETURNING id, name, enc', [name, req.user.id, wantEnc]);
    const groupId = g.rows[0].id;
    for (const uid of all) {
      await client.query('INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)', [groupId, uid]);
    }
    if (wantEnc) {
      for (const k of keyList) {
        const uid = Number(k.userId);
        if (!all.includes(uid) || typeof k.wrapped !== 'string') continue;
        await client.query('INSERT INTO group_keys (group_id, user_id, epoch, from_user, wrapped) VALUES ($1,$2,0,$3,$4)',
          [groupId, uid, req.user.id, k.wrapped.slice(0, 4000)]);
      }
    }
    await client.query('COMMIT');
    res.status(201).json(g.rows[0]);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

// 내가 속한 그룹 목록 (멤버 포함)
app.get('/api/groups', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT g.id, g.name,
       (SELECT json_agg(json_build_object('id', u.id, 'name', u.name, 'username', u.username))
          FROM group_members gm2 JOIN users u ON u.id = gm2.user_id WHERE gm2.group_id = g.id) AS members
     FROM groups g JOIN group_members gm ON gm.group_id = g.id
     WHERE gm.user_id=$1 ORDER BY g.id DESC`,
    [req.user.id]
  );
  res.json(rows);
}));

// 그룹 멤버 추가 (나와 친구인 사람만)
app.post('/api/groups/:id/members', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, req.user.id))) return res.status(403).json({ error: '그룹 멤버가 아닙니다' });
  const uid = Number((req.body || {}).userId);
  const f = await pool.query(
    `SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'`,
    [req.user.id, uid]
  );
  if (!f.rows[0]) return res.status(400).json({ error: '친구만 초대할 수 있습니다' });
  await pool.query('INSERT INTO group_members (group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [groupId, uid]);
  res.json({ ok: true });
}));

// 그룹 나가기
// 그룹 키 조회: 나에게 온 감싼 키, 멤버 공개키, 누가 어떤 세대 키를 가졌는지
app.get('/api/groups/:id/keys', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, req.user.id))) return res.status(403).json({ error: '그룹 멤버가 아닙니다' });
  const g = await pool.query('SELECT enc, epoch, needs_rotate FROM groups WHERE id=$1', [groupId]);
  const members = await pool.query(
    'SELECT u.id, u.name, u.pubkey FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id=$1', [groupId]);
  const mine = await pool.query('SELECT epoch, from_user, wrapped FROM group_keys WHERE group_id=$1 AND user_id=$2', [groupId, req.user.id]);
  const have = await pool.query('SELECT user_id, epoch FROM group_keys WHERE group_id=$1', [groupId]);
  res.json({
    enc: g.rows[0].enc, epoch: g.rows[0].epoch, needsRotate: g.rows[0].needs_rotate,
    members: members.rows, keys: mine.rows, have: have.rows,
  });
}));

// 감싼 그룹 키 저장: 보내는 사람은 본인이어야 하고, 받는 사람은 그룹 멤버여야 합니다
app.post('/api/groups/:id/keys', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, req.user.id))) return res.status(403).json({ error: '그룹 멤버가 아닙니다' });
  const list = Array.isArray((req.body || {}).keys) ? req.body.keys.slice(0, 500) : [];
  const memberIds = new Set(await groupMemberIds(groupId));
  const g = await pool.query('SELECT epoch FROM groups WHERE id=$1', [groupId]);
  let saved = 0;
  for (const k of list) {
    const uid = Number(k.userId), epoch = Number(k.epoch), wrapped = String(k.wrapped || '');
    if (!memberIds.has(uid) || !Number.isInteger(epoch) || epoch < 0 || epoch > g.rows[0].epoch) continue;
    if (!wrapped || wrapped.length > 4000) continue;
    await pool.query(
      'INSERT INTO group_keys (group_id, user_id, epoch, from_user, wrapped) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
      [groupId, uid, epoch, req.user.id, wrapped]);
    saved++;
  }
  res.json({ ok: true, saved });
}));

// 나간 멤버가 있으면 키 세대를 올립니다 (한 번만 올라감)
app.post('/api/groups/:id/rotate', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, req.user.id))) return res.status(403).json({ error: '그룹 멤버가 아닙니다' });
  const r = await pool.query(
    'UPDATE groups SET epoch = epoch + 1, needs_rotate = false WHERE id=$1 AND needs_rotate = true RETURNING epoch', [groupId]);
  if (r.rows[0]) return res.json({ epoch: r.rows[0].epoch, rotated: true });
  const g = await pool.query('SELECT epoch FROM groups WHERE id=$1', [groupId]);
  res.json({ epoch: g.rows[0].epoch, rotated: false });
}));

async function groupMemberIds(groupId) {
  const { rows } = await pool.query('SELECT user_id FROM group_members WHERE group_id=$1', [groupId]);
  return rows.map((r) => r.user_id);
}

app.post('/api/groups/:id/leave', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  await pool.query('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, req.user.id]);
  await pool.query('DELETE FROM group_keys WHERE group_id=$1 AND user_id=$2', [groupId, req.user.id]);
  // 암호화 그룹이면 다음 동기화 때 키를 새로 만들어서 나간 사람이 새 메시지를 못 읽게 합니다
  await pool.query('UPDATE groups SET needs_rotate = true WHERE id=$1 AND enc = true', [groupId]);
  res.json({ ok: true });
}));

app.get('/api/groups/:id/messages', auth, wrap(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!(await isGroupMember(groupId, req.user.id))) return res.status(403).json({ error: '그룹 멤버가 아닙니다' });
  const before = Number(req.query.before) || Number.MAX_SAFE_INTEGER;
  const { rows } = await pool.query(
    `SELECT m.id, m.sender_id, m.group_id, u.name AS sender_name, m.text, m.kind, m.file_id, m.created_at, m.enc, m.key_epoch, m.reply_to, m.edited_at, m.deleted,
       (SELECT json_agg(json_build_object('emoji', r.emoji, 'user', r.user_id)) FROM message_reactions r WHERE r.message_id = m.id) AS reactions,
       (SELECT name FROM files WHERE id = m.file_id) AS file_name
     FROM messages m JOIN users u ON u.id = m.sender_id
     WHERE m.group_id=$1 AND m.id < $2 ORDER BY m.id DESC LIMIT 50`,
    [groupId, before]
  );
  res.json(rows.reverse());
}));

// ---- 파일 업로드 / 다운로드 (DB 저장, 최대 2MB) ----
const ALLOWED_MIME = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf', 'text/plain', 'application/octet-stream'];
const INLINE_MIME = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

app.post(
  '/api/files',
  auth,
  express.raw({ type: () => true, limit: '20mb' }),
  wrap(async (req, res) => {
    const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const name = decodeURIComponent(String(req.headers['x-file-name'] || 'file')).slice(0, 200);
    if (!ALLOWED_MIME.includes(mime)) return res.status(415).json({ error: '이미지, PDF, 텍스트 파일만 보낼 수 있습니다' });
    if (!req.body || !req.body.length) return res.status(400).json({ error: '빈 파일입니다' });
    const { rows } = await pool.query(
      `INSERT INTO files (uploader_id, name, mime, size, data) VALUES ($1,$2,$3,$4,$5) RETURNING id, name, mime, size`,
      [req.user.id, name, mime, req.body.length, req.body]
    );
    res.status(201).json(rows[0]);
  })
);

app.get('/api/files/:id', auth, wrap(async (req, res) => {
  // 업로더이거나, 나에게 온 메시지 / 내가 속한 그룹 메시지에 첨부된 파일만 받을 수 있습니다
  const { rows } = await pool.query(
    `SELECT f.name, f.mime, f.data FROM files f
     WHERE f.id=$1 AND (
       f.uploader_id=$2
       OR EXISTS (SELECT 1 FROM messages m WHERE m.file_id=f.id AND (m.sender_id=$2 OR m.recipient_id=$2
            OR m.group_id IN (SELECT group_id FROM group_members WHERE user_id=$2)))
     )`,
    [Number(req.params.id), req.user.id]
  );
  const f = rows[0];
  if (!f) return res.status(404).json({ error: '파일을 찾을 수 없습니다' });
  const inline = INLINE_MIME.includes(f.mime);
  res.set('Content-Type', inline ? f.mime : 'application/octet-stream');
  res.set('Content-Disposition', (inline ? 'inline' : 'attachment') + "; filename*=UTF-8''" + encodeURIComponent(f.name));
  res.set('X-Content-Type-Options', 'nosniff');
  res.send(f.data);
}));

// ---- 관리자 ----
async function adminOnly(req, res, next) {
  const { rows } = await pool.query('SELECT is_admin FROM users WHERE id=$1', [req.user.id]);
  if (!rows[0] || !rows[0].is_admin) return res.status(403).json({ error: '관리자만 사용할 수 있습니다' });
  next();
}

app.get('/api/admin/reports', auth, adminOnly, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT r.id, r.reason, r.created_at,
       r.reporter_id, ru.username AS reporter_username,
       r.target_id, tu.username AS target_username, tu.banned AS target_banned
     FROM reports r
     JOIN users ru ON ru.id = r.reporter_id
     JOIN users tu ON tu.id = r.target_id
     ORDER BY r.id DESC LIMIT 200`
  );
  res.json(rows);
}));

app.post('/api/admin/reports/:id/resolve', auth, adminOnly, wrap(async (req, res) => {
  await pool.query('DELETE FROM reports WHERE id=$1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

app.get('/api/admin/users', auth, adminOnly, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, name, email, email_verified, banned, created_at FROM users ORDER BY id DESC LIMIT 200`
  );
  res.json(rows);
}));

app.post('/api/admin/users/:id/ban', auth, adminOnly, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: '자기 자신은 제한할 수 없습니다' });
  await pool.query('UPDATE users SET banned=$2 WHERE id=$1', [id, !!(req.body || {}).banned]);
  res.json({ ok: true });
}));

// ---- 실시간 (Socket.IO) ----
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });

io.use(async (socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET);
    if (socket.user.sid) {
      const r = await pool.query('SELECT 1 FROM sessions WHERE id=$1 AND revoked=false', [socket.user.sid]);
      if (!r.rows[0]) throw new Error('revoked');
    }
  } catch {
    return next(new Error('unauthorized'));
  }
  next();
});

// ===== 그룹 통화 상태 (메모리): groupId -> Map(socketId -> { userId, name }) =====
const calls = new Map();
const CALL_MAX = 6; // 메쉬 방식은 참여자 수가 늘수록 연결 수가 제곱으로 늘어나므로 상한을 둠
function callCount(gid) {
  const r = calls.get(gid);
  return r ? r.size : 0;
}
async function broadcastCall(gid) {
  const count = callCount(gid);
  const { rows } = await pool.query('SELECT user_id FROM group_members WHERE group_id=$1', [gid]);
  for (const r of rows) io.to('user:' + r.user_id).emit('call:state', { groupId: gid, count });
}

io.on('connection', (socket) => {
  const me = socket.user.id;
  socket.join('user:' + me);
  socket.on('disconnect', () => {
    // 마지막 접속 시각: 이 사용자의 연결이 모두 끊겼을 때만 기록
    const room = io.sockets.adapter.rooms.get('user:' + me);
    if (!room || room.size === 0) pool.query('UPDATE users SET last_seen=now() WHERE id=$1', [me]).catch(() => {});
  });

  // ----- 그룹 통화 시그널링: 서버는 SDP/ICE를 중계만 하고 미디어는 참여자끼리 직접 주고받음 -----
  socket.data.calls = new Set();
  const leaveCall = (gid) => {
    const room = calls.get(gid);
    if (!room || !room.delete(socket.id)) return;
    if (room.size === 0) calls.delete(gid);
    for (const sid of room.keys()) io.to(sid).emit('call:peer-left', { groupId: gid, sid: socket.id });
    socket.data.calls.delete(gid);
    broadcastCall(gid).catch(() => {});
  };
  socket.on('call:status', async ({ groupId } = {}, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const gid = Number(groupId);
    if (!(await isGroupMember(gid, me))) return reply({ error: '그룹 멤버가 아닙니다' });
    reply({ count: callCount(gid) });
  });
  socket.on('call:join', async ({ groupId } = {}, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const gid = Number(groupId);
    if (!(await isGroupMember(gid, me))) return reply({ error: '그룹 멤버가 아닙니다' });
    const { rows } = await pool.query('SELECT name FROM users WHERE id=$1', [me]);
    const name = (rows[0] && rows[0].name) || '참여자';
    if (!calls.has(gid)) calls.set(gid, new Map());
    const room = calls.get(gid);
    if (room.has(socket.id)) return reply({ error: '이미 참여 중입니다' });
    if ([...room.values()].some((p) => p.userId === me)) return reply({ error: '다른 기기에서 이미 통화 중입니다' });
    if (room.size >= CALL_MAX) return reply({ error: `통화는 최대 ${CALL_MAX}명까지 가능합니다` });
    const peers = [...room].map(([sid, p]) => ({ sid, name: p.name }));
    room.set(socket.id, { userId: me, name });
    socket.data.calls.add(gid);
    for (const sid of room.keys()) {
      if (sid !== socket.id) io.to(sid).emit('call:peer-joined', { groupId: gid, sid: socket.id, name });
    }
    broadcastCall(gid).catch(() => {});
    reply({ peers });
  });
  socket.on('call:signal', ({ groupId, to, data } = {}) => {
    const gid = Number(groupId);
    const room = calls.get(gid);
    if (!room || !data || !room.has(socket.id) || !room.has(to)) return;
    io.to(to).emit('call:signal', { groupId: gid, from: socket.id, data });
  });
  socket.on('call:leave', ({ groupId } = {}) => leaveCall(Number(groupId)));
  socket.on('disconnect', () => {
    for (const gid of [...socket.data.calls]) leaveCall(gid);
  });

  // 메시지 전송: { to, text, fileId } (1:1) 또는 { groupId, text, fileId } (그룹)
  socket.on('message:send', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      const p = payload || {};
      const text = String(p.text || '').trim();
      const fileId = p.fileId ? Number(p.fileId) : null;
      const enc = !!p.enc;
      const replyTo = p.replyTo ? Number(p.replyTo) : null;
      if (!text && !fileId) return reply({ error: '메시지를 입력하세요' });
      if (text.length > (enc ? 20000 : 2000)) return reply({ error: '메시지는 2000자 이내로 입력하세요' });

      let kind = 'text';
      if (fileId) {
        const fr = await pool.query('SELECT mime FROM files WHERE id=$1 AND uploader_id=$2', [fileId, me]);
        if (!fr.rows[0]) return reply({ error: '파일을 찾을 수 없습니다' });
        // 암호화된 파일은 서버가 종류를 알 수 없으므로 'file'로 저장 (실제 종류는 클라이언트가 복호화 후 판단)
        kind = enc ? 'file' : (INLINE_MIME.includes(fr.rows[0].mime) ? 'image' : 'file');
      }

      if (p.groupId) {
        // 그룹 메시지: 멤버 전원에게 전달
        const groupId = Number(p.groupId);
        if (!(await isGroupMember(groupId, me))) return reply({ error: '그룹 멤버가 아닙니다' });
        const gr = await pool.query('SELECT enc, epoch FROM groups WHERE id=$1', [groupId]);
        const gEnc = !!gr.rows[0].enc;
        if (gEnc !== enc) return reply({ error: gEnc ? '암호화된 그룹입니다. 새로고침 후 다시 보내세요' : '일반 그룹 메시지입니다' });
        // 키 세대가 바뀌었으면 클라이언트가 새 키로 다시 보내야 합니다
        if (enc && Number(p.epoch) !== gr.rows[0].epoch) return reply({ error: 'KEY_STALE' });
        const keyEpoch = enc ? gr.rows[0].epoch : null;
        const { rows } = await pool.query(
          `INSERT INTO messages (sender_id, group_id, text, kind, file_id, enc, key_epoch, reply_to) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id, sender_id, group_id, text, kind, file_id, created_at, enc, key_epoch, reply_to,
             (SELECT name FROM files WHERE id = messages.file_id) AS file_name`,
          [me, groupId, text, kind, fileId, enc, keyEpoch, replyTo]
        );
        const members = await pool.query('SELECT user_id FROM group_members WHERE group_id=$1', [groupId]);
        const nm = await pool.query('SELECT name FROM users WHERE id=$1', [me]);
        const msg = { ...rows[0], sender_name: nm.rows[0] ? nm.rows[0].name : '' };
        for (const m of members.rows) io.to('user:' + m.user_id).emit('message:new', msg);
        // 그룹 푸시 알림 (보낸 사람 제외)
        const gname = await pool.query('SELECT name FROM groups WHERE id=$1', [groupId]);
        notifyUsers(members.rows.map((r) => r.user_id), {
          title: gname.rows[0] ? gname.rows[0].name : '그룹',
          body: msg.sender_name + ': ' + (enc ? '새 메시지가 도착했습니다' : previewText(kind, text)),
          tag: 'group-' + groupId,
          url: '/',
        }, me).catch(() => {});
        return reply({ ok: true });
      }

      // 1:1 메시지: 수락된 친구에게만, 차단 관계가 아닐 때
      const to = Number(p.to);
      if (!to) return reply({ error: '받는 사람을 선택하세요' });
      if (await isBlocked(me, to)) return reply({ error: '차단 관계라 보낼 수 없습니다' });
      const f = await pool.query(
        `SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'`,
        [me, to]
      );
      if (!f.rows[0]) return reply({ error: '친구에게만 메시지를 보낼 수 있습니다' });

      // 자동 삭제 설정과 한 번만 보기 (사진 전송에만 적용)
      const ttlRow = await pool.query('SELECT ttl FROM conv_ttl WHERE a=$1 AND b=$2', [Math.min(me, to), Math.max(me, to)]);
      const expiresAt = ttlRow.rows[0] ? new Date(Date.now() + ttlRow.rows[0].ttl * 1000) : null;
      const viewOnce = !!p.viewOnce && !!fileId;
      const { rows } = await pool.query(
        `INSERT INTO messages (sender_id, recipient_id, text, kind, file_id, enc, reply_to, expires_at, view_once) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING id, sender_id, recipient_id, text, kind, file_id, read_at, created_at, enc, reply_to, view_once,
           (SELECT name FROM files WHERE id = messages.file_id) AS file_name`,
        [me, to, text, kind, fileId, enc, replyTo, expiresAt, viewOnce]
      );
      io.to(['user:' + to, 'user:' + me]).emit('message:new', rows[0]);
      // 1:1 푸시 알림
      const sn = await pool.query('SELECT name FROM users WHERE id=$1', [me]);
      notifyUsers([to], {
        title: sn.rows[0] ? sn.rows[0].name : '새 메시지',
        body: enc ? '새 메시지가 도착했습니다' : previewText(kind, text),
        tag: 'dm-' + me,
        url: '/',
      }, me).catch(() => {});
      reply({ ok: true });
    } catch (e) {
      console.error(e);
      reply({ error: '서버 오류가 발생했습니다' });
    }
  });

  // 메시지 수정·삭제 공통: 같은 대화의 참여자에게 알림
  async function emitToConversation(row, event, data) {
    if (row.group_id) {
      const { rows } = await pool.query('SELECT user_id FROM group_members WHERE group_id=$1', [row.group_id]);
      for (const r of rows) io.to('user:' + r.user_id).emit(event, data);
    } else {
      io.to(['user:' + row.sender_id, 'user:' + row.recipient_id]).emit(event, data);
    }
  }

  // 메시지 수정 (보낸 사람만, 암호화 여부는 그대로 유지)
  socket.on('message:edit', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      const p = payload || {};
      const id = Number(p.id);
      const text = String(p.text || '');
      if (!id || !text || text.length > 20000) return reply({ error: '수정할 내용을 입력하세요' });
      const { rows } = await pool.query(
        'UPDATE messages SET text=$3, edited_at=now() WHERE id=$1 AND sender_id=$2 AND deleted=false AND enc=$4 ' +
        'RETURNING id, sender_id, recipient_id, group_id, text, enc, edited_at',
        [id, me, text, !!p.enc]
      );
      if (!rows[0]) return reply({ error: '수정할 수 없는 메시지입니다' });
      await emitToConversation(rows[0], 'message:updated', rows[0]);
      reply({ ok: true });
    } catch (e) {
      console.error(e);
      reply({ error: '서버 오류가 발생했습니다' });
    }
  });

  // 메시지 삭제 (보낸 사람만): 내용과 첨부를 지우고 "삭제된 메시지"로 표시
  socket.on('message:delete', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      const id = Number((payload || {}).id);
      if (!id) return reply({ error: '잘못된 요청입니다' });
      const { rows } = await pool.query(
        "UPDATE messages SET deleted=true, text='', file_id=NULL, edited_at=NULL WHERE id=$1 AND sender_id=$2 AND deleted=false " +
        'RETURNING id, sender_id, recipient_id, group_id',
        [id, me]
      );
      if (!rows[0]) return reply({ error: '삭제할 수 없는 메시지입니다' });
      await emitToConversation(rows[0], 'message:deleted', { id, group_id: rows[0].group_id, recipient_id: rows[0].recipient_id, sender_id: rows[0].sender_id });
      reply({ ok: true });
    } catch (e) {
      console.error(e);
      reply({ error: '서버 오류가 발생했습니다' });
    }
  });

  // 이모지 반응 켜기/끄기 (대화 참여자만)
  const REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
  socket.on('reaction:toggle', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      const p = payload || {};
      const id = Number(p.id);
      const emoji = String(p.emoji || '');
      if (!id || !REACTIONS.includes(emoji)) return reply({ error: '잘못된 반응입니다' });
      const { rows } = await pool.query('SELECT sender_id, recipient_id, group_id FROM messages WHERE id=$1 AND deleted=false', [id]);
      const m = rows[0];
      if (!m) return reply({ error: '반응할 수 없는 메시지입니다' });
      const can = m.group_id ? await isGroupMember(m.group_id, me) : (m.sender_id === me || m.recipient_id === me);
      if (!can) return reply({ error: '반응할 수 없는 메시지입니다' });
      const del = await pool.query('DELETE FROM message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3', [id, me, emoji]);
      if (!del.rowCount) await pool.query('INSERT INTO message_reactions (message_id, user_id, emoji) VALUES ($1,$2,$3)', [id, me, emoji]);
      const list = await pool.query('SELECT emoji, user_id AS user FROM message_reactions WHERE message_id=$1 ORDER BY emoji', [id]);
      await emitToConversation({ ...m, id }, 'reaction:updated', { id, reactions: list.rows });
      reply({ ok: true });
    } catch (e) {
      console.error(e);
      reply({ error: '서버 오류가 발생했습니다' });
    }
  });

  // 1:1 대화 읽음 처리: 상대가 보낸 안 읽은 메시지를 모두 읽음으로 표시하고, 상대에게 알림
  socket.on('read:dm', async (payload) => {
    try {
      const other = Number((payload || {}).userId);
      if (!other) return;
      const { rows } = await pool.query(
        `UPDATE messages SET read_at=now()
         WHERE sender_id=$1 AND recipient_id=$2 AND read_at IS NULL
         RETURNING id, read_at`,
        [other, me]
      );
      // 읽음 표시 설정이 꺼져 있으면 상대에게 알리지 않습니다 (읽음 기록은 내 안 읽음 수를 위해 남김)
      const rcpt = rows.length ? (await pool.query("SELECT COALESCE((SELECT receipts FROM chat_prefs WHERE user_id=$1 AND target_id=$2 AND kind='dm'), (SELECT receipts_on FROM users WHERE id=$1), true) AS rc", [me, other])).rows[0].rc : false;
      if (rcpt) io.to('user:' + other).emit('read:dm', { by: me, ids: rows.map((r) => r.id) });
    } catch (e) {
      console.error(e);
    }
  });
});

// ---- 푸시 알림 (웹 푸시) ----
// VAPID 키: 환경변수(VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY)가 있으면 그 값을 쓰고, 없으면 DB에 자동 생성·저장합니다.
let VAPID_PUBLIC = null;
async function ensureVapid() {
  let pub = process.env.VAPID_PUBLIC_KEY;
  let priv = process.env.VAPID_PRIVATE_KEY;
  if (!pub || !priv) {
    const { rows } = await pool.query("SELECT value FROM app_settings WHERE key='vapid'");
    if (rows[0]) {
      const v = JSON.parse(rows[0].value);
      pub = v.publicKey;
      priv = v.privateKey;
    } else {
      const k = webpush.generateVAPIDKeys();
      pub = k.publicKey;
      priv = k.privateKey;
      await pool.query(
        "INSERT INTO app_settings (key, value) VALUES ('vapid', $1) ON CONFLICT (key) DO NOTHING",
        [JSON.stringify({ publicKey: pub, privateKey: priv })]
      );
    }
  }
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@messenger.local', pub, priv);
  VAPID_PUBLIC = pub;
}

app.get('/api/push/key', auth, (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC });
});

app.post('/api/push/subscribe', auth, wrap(async (req, res) => {
  const s = (req.body || {}).subscription || {};
  if (!s.endpoint || !s.keys || !s.keys.p256dh || !s.keys.auth) {
    return res.status(400).json({ error: '잘못된 구독 정보입니다' });
  }
  await pool.query(
    `INSERT INTO push_subs (user_id, endpoint, p256dh, auth) VALUES ($1,$2,$3,$4)
     ON CONFLICT (endpoint) DO UPDATE SET user_id=$1, p256dh=$3, auth=$4`,
    [req.user.id, s.endpoint, s.keys.p256dh, s.keys.auth]
  );
  res.status(201).json({ ok: true });
}));

app.post('/api/push/unsubscribe', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM push_subs WHERE endpoint=$1 AND user_id=$2',
    [String((req.body || {}).endpoint || ''), req.user.id]);
  res.json({ ok: true });
}));

function previewText(kind, text) {
  if (kind === 'image') return '사진';
  if (kind === 'file') return '파일';
  return String(text || '').slice(0, 100);
}

// 앱이 연결되어 있지 않은 사용자에게만 푸시를 보냅니다 (연결 중이면 소켓으로 이미 받음)
async function notifyUsers(userIds, payload, exceptUserId) {
  const targets = [...new Set(userIds)].filter((id) => id !== exceptUserId && !io.sockets.adapter.rooms.get('user:' + id));
  if (!targets.length) return;
  const { rows } = await pool.query(
    'SELECT id, endpoint, p256dh, auth FROM push_subs WHERE user_id = ANY($1::int[])',
    [targets]
  );
  const body = JSON.stringify(payload);
  await Promise.all(rows.map((s) =>
    webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, body, { TTL: 3600 })
      .catch(async (e) => {
        if (e.statusCode === 404 || e.statusCode === 410) await pool.query('DELETE FROM push_subs WHERE id=$1', [s.id]);
        else console.error('푸시 발송 실패:', e.statusCode || e.message);
      })
  ));
}

const PORT = process.env.PORT || 3000;
init()
  .then(async () => {
    await ensureVapid();
    // 하루가 지난 미인증 계정 자동 삭제 (1시간마다 확인)
    const purge = () =>
      pool
        .query(`DELETE FROM users WHERE email_verified = false AND created_at < now() - interval '1 day'`)
        .catch((e) => console.error('미인증 계정 정리 실패:', e.message));
    purge();
    setInterval(purge, 60 * 60 * 1000).unref();
    server.listen(PORT, () => console.log(`서버 시작: http://localhost:${PORT}`));
  })
  .catch((e) => {
    console.error('DB 초기화 실패', e);
    process.exit(1);
  });

// ---- 자동 삭제: 만료된 1:1 메시지를 지우고 양쪽 화면에 알립니다 (30초마다 확인) ----
async function purgeExpired() {
  const { rows } = await pool.query(
    'SELECT id, sender_id, recipient_id, file_id FROM messages WHERE expires_at IS NOT NULL AND expires_at <= now() AND deleted=false LIMIT 500');
  for (const r of rows) {
    await pool.query("UPDATE messages SET deleted=true, text='', file_id=NULL, edited_at=NULL, expires_at=NULL WHERE id=$1", [r.id]);
    if (r.file_id) await pool.query('DELETE FROM files WHERE id=$1', [r.file_id]).catch(() => {});
    io.to(['user:' + r.sender_id, 'user:' + r.recipient_id]).emit('message:deleted', { id: r.id });
  }
}
setInterval(() => purgeExpired().catch((e) => console.error('자동 삭제 오류:', e)), 30000);

// ---- 예약 전송: 시간이 되면 메시지를 보냅니다 (10초마다 확인) ----
async function sendDueScheduled() {
  const { rows } = await pool.query('SELECT id, sender_id, recipient_id, text, file_id FROM scheduled_messages WHERE send_at <= now() ORDER BY send_at LIMIT 100');
  for (const r of rows) {
    await pool.query('DELETE FROM scheduled_messages WHERE id=$1', [r.id]);
    const f = await pool.query("SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2 AND status='accepted'", [r.sender_id, r.recipient_id]);
    if (!f.rows[0] || (await isBlocked(r.sender_id, r.recipient_id))) {
      if (r.file_id) await pool.query('DELETE FROM files WHERE id=$1', [r.file_id]).catch(() => {});
      continue;
    }
    const { rows: m } = await pool.query(
      'INSERT INTO messages (sender_id, recipient_id, text, kind, file_id, enc) VALUES ($1,$2,$3,$4,$5,true) ' +
      'RETURNING id, sender_id, recipient_id, text, kind, file_id, read_at, created_at, enc, ' +
      '(SELECT name FROM files WHERE id = messages.file_id) AS file_name',
      [r.sender_id, r.recipient_id, r.text, r.file_id ? 'file' : 'text', r.file_id]);
    io.to(['user:' + r.recipient_id, 'user:' + r.sender_id]).emit('message:new', m[0]);
    const sn = await pool.query('SELECT name FROM users WHERE id=$1', [r.sender_id]);
    notifyUsers([r.recipient_id], {
      title: sn.rows[0] ? sn.rows[0].name : '새 메시지',
      body: '새 메시지가 도착했습니다',
      tag: 'dm-' + r.sender_id,
      url: '/',
    }, r.sender_id).catch(() => {});
  }
}
setInterval(() => sendDueScheduled().catch((e) => console.error('예약 전송 오류:', e)), 10000);

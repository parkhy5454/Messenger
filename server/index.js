const http = require('http');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { pool, init } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET 환경 변수가 필요합니다.');
  process.exit(1);
}

const app = express();
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

async function sendCode(email, code) {
  if (!mailer) {
    console.log(`[개발] ${email} 인증 코드: ${code}`);
    return;
  }
  await mailer.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: '[Messenger] 이메일 인증 코드',
    text: `인증 코드: ${code}\n10분 안에 입력해 주세요.`,
  });
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const issue = (u) => jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '30d' });
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: '로그인이 필요합니다' });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: '로그인이 만료되었습니다' });
  }
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
app.post('/api/auth/signup', wrap(async (req, res) => {
  const { username, password, name, email } = req.body || {};
  const uname = String(username || '').toLowerCase();
  if (!USERNAME_RE.test(uname)) return res.status(400).json({ error: '아이디는 영소문자·숫자·_ 조합 3~20자입니다' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: '비밀번호는 8자 이상이어야 합니다' });
  if (!name || !email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: '이름과 올바른 이메일을 입력하세요' });

  const hash = await bcrypt.hash(password, 10);
  const code = String(crypto.randomInt(100000, 1000000));
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
  await sendCode(email, code);
  res.status(201).json({ ok: true });
}));

app.post('/api/auth/verify', wrap(async (req, res) => {
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

app.post('/api/auth/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  const { rows } = await pool.query(
    'SELECT id, username, password_hash, email_verified FROM users WHERE username=$1',
    [String(username || '').toLowerCase()]
  );
  const u = rows[0];
  if (!u || !u.password_hash || !(await bcrypt.compare(String(password || ''), u.password_hash))) {
    return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다' });
  }
  if (!u.email_verified) return res.status(403).json({ error: '이메일 인증을 먼저 완료하세요' });
  res.json({ token: issue(u) });
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
  res.redirect('/#token=' + issue(u));
}));

// ---- 사용자·친구 ----
app.get('/api/me', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, name FROM users WHERE id=$1', [req.user.id]);
  res.json(rows[0]);
}));

app.post('/api/friends', auth, wrap(async (req, res) => {
  const uname = String((req.body || {}).username || '').toLowerCase();
  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1 AND email_verified', [uname]);
  const f = rows[0];
  if (!f) return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
  if (f.id === req.user.id) return res.status(400).json({ error: '자기 자신은 추가할 수 없습니다' });
  if (await isBlocked(req.user.id, f.id)) return res.status(403).json({ error: '차단 관계라 추가할 수 없습니다' });
  await pool.query(
    'INSERT INTO friendships (user_id, friend_id) VALUES ($1,$2), ($2,$1) ON CONFLICT DO NOTHING',
    [req.user.id, f.id]
  );
  res.status(201).json({ ok: true });
}));

app.get('/api/friends', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.name FROM friendships f
     JOIN users u ON u.id = f.friend_id
     WHERE f.user_id=$1 ORDER BY u.name`,
    [req.user.id]
  );
  res.json(rows);
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
app.get('/api/messages/:userId', auth, wrap(async (req, res) => {
  const other = Number(req.params.userId);
  const me = req.user.id;
  const { rows } = await pool.query(
    `SELECT id, sender_id, recipient_id, text, created_at FROM messages
     WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)
     ORDER BY id DESC LIMIT 50`,
    [me, other]
  );
  res.json(rows.reverse());
}));

// ---- 실시간 (Socket.IO) ----
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e5 });

io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET);
    next();
  } catch {
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  socket.join('user:' + socket.user.id);

  socket.on('message:send', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    try {
      const to = Number((payload || {}).to);
      const text = String((payload || {}).text || '').trim();
      if (!to || !text || text.length > 2000) return reply({ error: '메시지가 올바르지 않습니다' });
      if (await isBlocked(socket.user.id, to)) return reply({ error: '차단 관계라 보낼 수 없습니다' });
      const f = await pool.query('SELECT 1 FROM friendships WHERE user_id=$1 AND friend_id=$2', [socket.user.id, to]);
      if (!f.rows[0]) return reply({ error: '친구에게만 메시지를 보낼 수 있습니다' });

      const { rows } = await pool.query(
        `INSERT INTO messages (sender_id, recipient_id, text) VALUES ($1,$2,$3)
         RETURNING id, sender_id, recipient_id, text, created_at`,
        [socket.user.id, to, text]
      );
      io.to(['user:' + to, 'user:' + socket.user.id]).emit('message:new', rows[0]);
      reply({ ok: true });
    } catch (e) {
      console.error(e);
      reply({ error: '서버 오류가 발생했습니다' });
    }
  });
});

const PORT = process.env.PORT || 3000;
init()
  .then(() => server.listen(PORT, () => console.log(`서버 시작: http://localhost:${PORT}`)))
  .catch((e) => {
    console.error('DB 초기화 실패', e);
    process.exit(1);
  });

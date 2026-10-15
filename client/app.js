const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token');
let me = null, socket = null, current = null, oldestId = null, chatMsgs = [];
let pendingEmail = '', resetEmail = '';
let friends = [], chats = [];
let activeTab = 'friends';
const blobCache = new Map();

// 카카오 로그인 후 주소 뒤에 붙은 토큰을 저장하고 주소를 정리합니다.
const tokenMatch = location.hash.match(/token=([^&]+)/);
if (tokenMatch) {
  token = tokenMatch[1];
  localStorage.setItem('token', token);
  history.replaceState(null, '', location.pathname);
}

// ---------- 공통 유틸 ----------
const VIEWS = ['auth', 'verify', 'main', 'reset', 'pw', 'profile', 'blocks', 'group', 'admin'];
function showView(name) {
  for (const v of VIEWS) $('#view-' + v).hidden = v !== name;
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const r = await fetch(path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || '요청에 실패했습니다 (' + r.status + ')');
  return j;
}

// 첨부 파일은 인증 헤더가 필요해서 fetch 후 blob 주소로 바꿔 씁니다.
async function loadBlob(id) {
  if (!blobCache.has(id)) {
    const r = await fetch('/api/files/' + id, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error('파일을 불러올 수 없습니다');
    blobCache.set(id, URL.createObjectURL(await r.blob()));
  }
  return blobCache.get(id);
}

function btn(label, fn, cls) {
  const b = document.createElement('button');
  b.textContent = label;
  if (cls) b.className = cls;
  b.onclick = async () => {
    try { await fn(); } catch (err) { alert(err.message); }
  };
  return b;
}

// 이름 기반 색 아바타 (카카오톡처럼 사각 둥근 모서리)
const AV_COLORS = ['#f28b82', '#fbbc04', '#34a853', '#4285f4', '#a142f4', '#00acc1', '#ff7043', '#8d6e63', '#5c6bc0', '#26a69a'];
function avatarEl(name, cls) {
  const s = String(name || '?').trim() || '?';
  let h = 0;
  for (const ch of s) h = (h * 31 + ch.codePointAt(0)) >>> 0;
  const d = document.createElement('div');
  d.className = 'av ' + (cls || '');
  d.style.background = AV_COLORS[h % AV_COLORS.length];
  d.textContent = s[0].toUpperCase();
  return d;
}

function dayKey(iso) {
  const d = new Date(iso);
  return d.getFullYear() + '-' + (d.getMonth() + 1) + '-' + d.getDate();
}
function dateLabel(iso) {
  const d = new Date(iso);
  return d.getFullYear() + '년 ' + (d.getMonth() + 1) + '월 ' + d.getDate() + '일';
}
function timeLabel(iso) {
  const d = new Date(iso);
  const h = d.getHours();
  return (h < 12 ? '오전 ' : '오후 ') + (h % 12 || 12) + ':' + String(d.getMinutes()).padStart(2, '0');
}
// 목록용: 오늘이면 시간, 아니면 날짜
function listTime(iso) {
  if (!iso) return '';
  const d = new Date(iso), now = new Date();
  if (dayKey(iso) === dayKey(now.toISOString())) return timeLabel(iso);
  return (d.getMonth() + 1) + '/' + d.getDate();
}
function previewOf(last) {
  if (!last) return '';
  if (last.kind === 'image') return '사진';
  if (last.kind === 'file') return '파일';
  return last.text || '';
}

// ---------- 화면 전환 ----------
function showTab(name) {
  activeTab = name;
  for (const t of ['friends', 'chats', 'settings']) $('#tab-' + t).hidden = t !== name;
  document.querySelectorAll('#tabbar button').forEach((b) => b.classList.toggle('on', b.dataset.tab === name));
}
function openMain(tab) {
  showView('main');
  showTab(tab || activeTab);
}
function setChatOpen(open) {
  $('#view-main').classList.toggle('chat-open', open);
}
function renderMe() {
  $('#me').textContent = me.name;
  $('#me-status').textContent = (me.status_msg ? me.status_msg : '@' + me.username);
  const av = $('#me-av');
  av.innerHTML = '';
  av.appendChild(avatarEl(me.name, 'lg'));
}

document.querySelectorAll('#tabbar button').forEach((b) => {
  b.onclick = () => {
    setChatOpen(false);
    current = null;
    showTab(b.dataset.tab);
    if (b.dataset.tab === 'chats') renderList();
  };
});
$('#chat-back').onclick = () => {
  current = null;
  setChatOpen(false);
  renderList();
};

// ---------- 로그인 / 회원가입 / 인증 ----------
$('#tab-login').onclick = () => { $('#login-form').hidden = false; $('#signup-form').hidden = true; setTab('login'); };
$('#tab-signup').onclick = () => { $('#login-form').hidden = true; $('#signup-form').hidden = false; setTab('signup'); };
function setTab(t) {
  $('#tab-login').classList.toggle('active', t === 'login');
  $('#tab-signup').classList.toggle('active', t === 'signup');
  $('#auth-msg').textContent = '';
}

$('#login-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    const r = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('#li-user').value, password: $('#li-pass').value }),
    });
    token = r.token;
    localStorage.setItem('token', token);
    await start();
  } catch (err) {
    $('#auth-msg').textContent = err.message;
  }
};

$('#signup-form').onsubmit = async (e) => {
  e.preventDefault();
  pendingEmail = $('#su-email').value;
  try {
    await api('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#su-user').value,
        name: $('#su-name').value,
        email: pendingEmail,
        password: $('#su-pass').value,
      }),
    });
    $('#verify-msg').textContent = '인증 코드를 메일로 보냈습니다. 스팸함도 확인하세요.';
    showView('verify');
  } catch (err) {
    $('#auth-msg').textContent = err.message;
  }
};

$('#verify-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/auth/verify', {
      method: 'POST',
      body: JSON.stringify({ email: pendingEmail, code: $('#vf-code').value.trim() }),
    });
    showView('auth');
    setTab('login');
    $('#auth-msg').textContent = '인증이 끝났습니다. 로그인하세요.';
  } catch (err) {
    $('#verify-msg').textContent = err.message;
  }
};

// ---------- 비밀번호 찾기 / 변경 ----------
$('#go-forgot').onclick = () => {
  $('#fg-email').value = '';
  $('#forgot-form').hidden = false;
  $('#reset-form').hidden = true;
  $('#reset-msg').textContent = '';
  showView('reset');
};
$('#reset-back').onclick = () => { showView('auth'); setTab('login'); };

$('#forgot-form').onsubmit = async (e) => {
  e.preventDefault();
  resetEmail = $('#fg-email').value.trim();
  try {
    const r = await api('/api/auth/forgot', { method: 'POST', body: JSON.stringify({ email: resetEmail }) });
    $('#reset-msg').textContent = r.message;
    $('#forgot-form').hidden = true;
    $('#reset-form').hidden = false;
  } catch (err) {
    $('#reset-msg').textContent = err.message;
  }
};

$('#reset-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/auth/reset', {
      method: 'POST',
      body: JSON.stringify({ email: resetEmail, code: $('#rs-code').value.trim(), password: $('#rs-pass').value }),
    });
    showView('auth');
    setTab('login');
    $('#auth-msg').textContent = '비밀번호가 변경되었습니다. 새 비밀번호로 로그인하세요.';
  } catch (err) {
    $('#reset-msg').textContent = err.message;
  }
};

$('#btn-pw').onclick = () => {
  $('#pw-cur').value = '';
  $('#pw-new').value = '';
  $('#pw-msg').textContent = '';
  showView('pw');
};
$('#pw-back').onclick = () => openMain('settings');
$('#pw-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/me/password', {
      method: 'POST',
      body: JSON.stringify({ current: $('#pw-cur').value, next: $('#pw-new').value }),
    });
    $('#pw-msg').textContent = '비밀번호가 변경되었습니다.';
    $('#pw-cur').value = '';
    $('#pw-new').value = '';
  } catch (err) {
    $('#pw-msg').textContent = err.message;
  }
};

// ---------- 프로필 / 차단 목록 / 관리자 ----------
$('#btn-profile').onclick = () => {
  $('#pf-name').value = me.name;
  $('#pf-status').value = me.status_msg || '';
  $('#pf-msg').textContent = '';
  showView('profile');
};
$('#profile-back').onclick = () => openMain('settings');
$('#profile-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/me', {
      method: 'PATCH',
      body: JSON.stringify({ name: $('#pf-name').value.trim(), statusMsg: $('#pf-status').value.trim() }),
    });
    me = await api('/api/me');
    renderMe();
    $('#pf-msg').textContent = '저장되었습니다.';
  } catch (err) {
    $('#pf-msg').textContent = err.message;
  }
};

$('#btn-blocks').onclick = loadBlocks;
$('#blocks-back').onclick = () => openMain('settings');
async function loadBlocks() {
  showView('blocks');
  const list = await api('/api/blocks');
  const ul = $('#block-list');
  ul.innerHTML = '';
  if (!list.length) ul.innerHTML = '<li class="muted">차단한 사용자가 없습니다</li>';
  for (const b of list) {
    const li = document.createElement('li');
    li.textContent = b.name + '  @' + b.username + ' ';
    li.appendChild(btn('해제', async () => {
      await api('/api/blocks/' + b.id, { method: 'DELETE' });
      await loadBlocks();
      await loadList();
    }, 'ghost'));
    ul.appendChild(li);
  }
}

$('#btn-admin').onclick = loadAdmin;
$('#admin-back').onclick = () => openMain('settings');
async function loadAdmin() {
  showView('admin');
  const [reports, users] = await Promise.all([api('/api/admin/reports'), api('/api/admin/users')]);
  const rl = $('#admin-reports');
  rl.innerHTML = '';
  if (!reports.length) rl.innerHTML = '<li class="muted">접수된 신고가 없습니다</li>';
  for (const r of reports) {
    const li = document.createElement('li');
    li.textContent = '@' + r.reporter_username + ' → @' + r.target_username + ' : ' + r.reason + ' ';
    li.appendChild(btn('신고 해결', async () => {
      await api('/api/admin/reports/' + r.id + '/resolve', { method: 'POST' });
      await loadAdmin();
    }, 'ghost'));
    li.appendChild(btn(r.target_banned ? '제한 해제' : '이용 제한', async () => {
      await api('/api/admin/users/' + r.target_id + '/ban', { method: 'POST', body: JSON.stringify({ banned: !r.target_banned }) });
      await loadAdmin();
    }, 'ghost'));
    rl.appendChild(li);
  }
  const ul = $('#admin-users');
  ul.innerHTML = '';
  for (const u of users) {
    const li = document.createElement('li');
    li.textContent = '@' + u.username + ' ' + u.name + (u.email_verified ? '' : ' (미인증)') + (u.banned ? ' [제한됨]' : '') + ' ';
    if (u.id !== me.id) {
      li.appendChild(btn(u.banned ? '제한 해제' : '이용 제한', async () => {
        await api('/api/admin/users/' + u.id + '/ban', { method: 'POST', body: JSON.stringify({ banned: !u.banned }) });
        await loadAdmin();
      }, 'ghost'));
    }
    ul.appendChild(li);
  }
}

// ---------- 그룹 만들기 ----------
$('#btn-newgroup').onclick = () => {
  $('#gr-name').value = '';
  $('#gr-msg').textContent = '';
  const box = $('#gr-friends');
  box.innerHTML = '';
  if (!friends.length) box.innerHTML = '<p class="muted">친구가 없습니다. 먼저 친구를 추가하세요.</p>';
  for (const f of friends) {
    const l = document.createElement('label');
    const c = document.createElement('input');
    c.type = 'checkbox';
    c.value = f.id;
    l.append(c, f.name + '  @' + f.username);
    box.appendChild(l);
  }
  showView('group');
};
$('#gr-back').onclick = () => openMain('friends');
$('#gr-form').onsubmit = async (e) => {
  e.preventDefault();
  const ids = [...document.querySelectorAll('#gr-friends input:checked')].map((c) => Number(c.value));
  try {
    await api('/api/groups', {
      method: 'POST',
      body: JSON.stringify({ name: $('#gr-name').value.trim(), memberIds: ids }),
    });
    openMain('chats');
    await loadList();
  } catch (err) {
    $('#gr-msg').textContent = err.message;
  }
};

// ---------- 시작 / 소켓 ----------
async function start() {
  try {
    me = await api('/api/me');
  } catch (err) {
    if (err.message.includes('제한')) alert(err.message);
    return logout();
  }
  openMain('friends');
  renderMe();
  $('#btn-admin').hidden = !me.is_admin;
  await loadRequests();
  await loadList();
  connectSocket();
  enablePush(true).catch(() => {}); // 이미 허용된 경우에만 조용히 구독
}

function connectSocket() {
  if (socket) socket.disconnect();
  socket = io({ auth: { token } });
  socket.on('message:new', onMessage);
  socket.on('read:dm', onRead);
  socket.on('connect_error', (err) => {
    if (err.message === 'unauthorized') logout();
  });
}

// 친구 목록과 대화 목록(마지막 메시지, 안 읽은 수)을 함께 불러옵니다
async function loadList() {
  [friends, chats] = await Promise.all([api('/api/friends'), api('/api/chats')]);
  renderFriends();
  renderList();
}

// ---------- 친구 탭 ----------
function renderFriends() {
  const q = $('#fsearch').value.trim().toLowerCase();
  const ul = $('#friends');
  ul.innerHTML = '';
  for (const f of friends) {
    if (q && !(f.name + f.username).toLowerCase().includes(q)) continue;
    const li = document.createElement('li');
    li.appendChild(avatarEl(f.name));
    const main = document.createElement('div');
    main.className = 'row-main';
    main.innerHTML = '<div class="row-name"></div><div class="row-sub"></div>';
    main.querySelector('.row-name').textContent = f.name;
    main.querySelector('.row-sub').textContent = f.status_msg || '@' + f.username;
    li.appendChild(main);
    li.onclick = () => openChat({ type: 'dm', id: f.id, name: f.name, username: f.username });
    ul.appendChild(li);
  }
  if (!ul.children.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = '친구가 없습니다. 위에서 아이디로 친구를 추가하세요.';
    ul.appendChild(li);
  }
}
$('#fsearch').oninput = renderFriends;

// 받은 친구 요청 (수락 / 거절)
async function loadRequests() {
  const list = await api('/api/friends/requests');
  const ul = $('#requests');
  ul.innerHTML = '';
  $('#req-box').hidden = list.length === 0;
  for (const r of list) {
    const li = document.createElement('li');
    li.appendChild(avatarEl(r.name));
    const main = document.createElement('div');
    main.className = 'row-main';
    main.innerHTML = '<div class="row-name"></div><div class="row-sub"></div>';
    main.querySelector('.row-name').textContent = r.name;
    main.querySelector('.row-sub').textContent = '@' + r.username + ' · 친구 요청';
    li.appendChild(main);
    li.appendChild(btn('수락', async () => {
      await api('/api/friends/accept', { method: 'POST', body: JSON.stringify({ userId: r.id }) });
      await loadRequests();
      await loadList();
    }));
    li.appendChild(btn('거절', async () => {
      await api('/api/friends/decline', { method: 'POST', body: JSON.stringify({ userId: r.id }) });
      await loadRequests();
    }, 'ghost'));
    ul.appendChild(li);
  }
}

$('#add-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    const r = await api('/api/friends', { method: 'POST', body: JSON.stringify({ username: $('#add-input').value.trim() }) });
    $('#add-input').value = '';
    alert(r.status === 'accepted' ? '친구가 되었습니다.' : '친구 요청을 보냈습니다. 상대가 수락하면 친구가 됩니다.');
    await loadList();
  } catch (err) {
    alert(err.message);
  }
};

// ---------- 대화 탭 ----------
function renderList() {
  const q = $('#search').value.trim().toLowerCase();
  const ul = $('#list');
  ul.innerHTML = '';
  const items = chats
    .filter((c) => !q || c.name.toLowerCase().includes(q))
    .sort((a, b) => {
      const ta = a.last ? Date.parse(a.last.created_at) : 0;
      const tb = b.last ? Date.parse(b.last.created_at) : 0;
      return tb - ta;
    });
  for (const c of items) ul.appendChild(chatItem(c));
  if (!items.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = '대화가 없습니다. 친구 탭에서 친구를 추가하세요.';
    ul.appendChild(li);
  }

  // 하단 탭의 "대화" 뱃지: 안 읽은 1:1 메시지 총합
  const total = chats.reduce((sum, c) => sum + (c.type === 'dm' ? c.unread || 0 : 0), 0);
  const badge = $('#chat-badge');
  badge.hidden = !total;
  badge.textContent = total > 99 ? '99+' : String(total);
}
$('#search').oninput = renderList;

function chatItem(c) {
  const li = document.createElement('li');
  li.onclick = () => openChat({ type: c.type, id: c.id, name: c.name, username: c.username });
  li.appendChild(avatarEl(c.name));

  const main = document.createElement('div');
  main.className = 'row-main';
  const name = document.createElement('div');
  name.className = 'row-name';
  name.textContent = c.name;
  if (c.type === 'group') {
    const n = document.createElement('span');
    n.className = 'muted';
    n.style.marginLeft = '6px';
    n.style.fontSize = '12px';
    n.textContent = c.members + '명';
    name.appendChild(n);
  }
  const sub = document.createElement('div');
  sub.className = 'row-sub';
  let previewText = previewOf(c.last);
  if (c.type === 'group' && c.last && c.last.sender_name && c.last.kind !== 'image') {
    previewText = c.last.sender_name + ': ' + previewText;
  }
  sub.textContent = previewText;
  main.append(name, sub);
  li.appendChild(main);

  const side = document.createElement('div');
  side.className = 'row-side';
  const time = document.createElement('div');
  time.className = 'row-time';
  time.textContent = c.last ? listTime(c.last.created_at) : '';
  side.appendChild(time);
  if (c.type === 'dm' && c.unread) {
    const b = document.createElement('b');
    b.className = 'badge';
    b.textContent = c.unread > 99 ? '99+' : c.unread;
    side.appendChild(b);
  }
  li.appendChild(side);
  return li;
}

// ---------- 채팅 화면 ----------
function isCurrent(t) {
  return current && current.type === t.type && current.id === t.id;
}

async function openChat(t) {
  current = t;
  oldestId = null;
  chatMsgs = [];
  setChatOpen(true);
  $('#chat-title').textContent = t.name;
  $('#dm-actions').hidden = t.type !== 'dm';
  $('#group-actions').hidden = t.type !== 'group';
  $('#compose').hidden = false;
  $('#chat-box').innerHTML = '';
  await loadMessages(true);
  if (t.type === 'dm') {
    socket.emit('read:dm', { userId: t.id });
    const c = chats.find((x) => x.type === 'dm' && x.id === t.id);
    if (c) c.unread = 0;
    renderList();
  }
  $('#msg-input').focus();
}

function historyPath(t, before) {
  const base = t.type === 'group' ? '/api/groups/' + t.id + '/messages' : '/api/messages/' + t.id;
  return base + (before ? '?before=' + before : '');
}

// 처음에는 최근 메시지, "더 보기"는 이전 메시지를 위에 붙입니다
async function loadMessages(initial) {
  const rows = await api(historyPath(current, oldestId));
  if (rows.length) oldestId = rows[0].id;
  $('#more').hidden = rows.length < 50;
  chatMsgs = initial ? rows : rows.concat(chatMsgs);
  renderChat(initial ? 'bottom' : 'keep');
}
$('#more').onclick = () => loadMessages(false);

function renderChat(mode) {
  const box = $('#chat-box');
  const prevH = box.scrollHeight, prevTop = box.scrollTop;
  box.innerHTML = '';
  box.appendChild(buildMsgs(chatMsgs, null));
  if (mode === 'bottom') box.scrollTop = box.scrollHeight;
  else box.scrollTop = prevTop + (box.scrollHeight - prevH);
}

// 날짜 구분선과 같은 사람 연속 메시지(아바타 생략)를 처리해서 조각(fragment)을 만듭니다
function buildMsgs(list, prev) {
  const frag = document.createDocumentFragment();
  for (const m of list) {
    const day = dayKey(m.created_at);
    const sameDay = !!prev && prev.day === day;
    if (!sameDay) {
      const sep = document.createElement('div');
      sep.className = 'day-sep';
      const sp = document.createElement('span');
      sp.textContent = dateLabel(m.created_at);
      sep.appendChild(sp);
      frag.appendChild(sep);
    }
    const cont = sameDay && prev.sender_id === m.sender_id;
    frag.appendChild(makeMsg(m, cont));
    prev = { sender_id: m.sender_id, day };
  }
  return frag;
}

function appendMsg(m) {
  const last = chatMsgs[chatMsgs.length - 1];
  chatMsgs.push(m);
  const prev = last ? { sender_id: last.sender_id, day: dayKey(last.created_at) } : null;
  const box = $('#chat-box');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  box.appendChild(buildMsgs([m], prev));
  if (atBottom || m.sender_id === me.id) box.scrollTop = box.scrollHeight;
}

function makeMsg(m, cont) {
  const mine = m.sender_id === me.id;
  const row = document.createElement('div');
  row.className = 'msg-row ' + (mine ? 'me' : 'them') + (cont ? ' cont' : ' first');
  row.dataset.id = m.id;

  if (!mine) {
    const slot = document.createElement('div');
    slot.className = 'av-slot';
    if (!cont) slot.appendChild(avatarEl(m.sender_name || (current ? current.name : '?'), 'sm'));
    row.appendChild(slot);
  }

  const col = document.createElement('div');
  col.className = 'col';
  if (!mine && !cont && current && current.type === 'group' && m.sender_name) {
    const who = document.createElement('div');
    who.className = 'sender';
    who.textContent = m.sender_name;
    col.appendChild(who);
  }

  const line = document.createElement('div');
  line.className = 'line';

  const bubble = document.createElement('div');
  bubble.className = 'msg ' + (mine ? 'me' : 'them');
  if (m.kind === 'image' && m.file_id) {
    const img = document.createElement('img');
    img.className = 'thumb';
    img.alt = '사진';
    loadBlob(m.file_id).then((url) => { img.src = url; }).catch(() => { img.alt = '[이미지를 불러올 수 없음]'; });
    bubble.appendChild(img);
  } else if (m.kind === 'file' && m.file_id) {
    const a = document.createElement('a');
    a.href = '#';
    a.textContent = '📎 ' + (m.file_name || '첨부 파일') + ' 받기';
    a.onclick = async (e) => {
      e.preventDefault();
      try {
        const url = await loadBlob(m.file_id);
        const d = document.createElement('a');
        d.href = url;
        d.download = m.file_name || 'file';
        d.click();
      } catch (err) { alert(err.message); }
    };
    bubble.appendChild(a);
  }
  if (m.text) {
    const t = document.createElement('div');
    t.textContent = m.text;
    bubble.appendChild(t);
  }

  // 메타: 1:1에서 내 메시지는 "1"(안 읽음) 표시, 시간
  const meta = document.createElement('div');
  meta.className = 'meta';
  if (mine && current && current.type === 'dm') {
    const r = document.createElement('span');
    r.className = 'read';
    r.textContent = m.read_at ? '' : '1';
    meta.appendChild(r);
  }
  const tm = document.createElement('span');
  tm.textContent = timeLabel(m.created_at);
  meta.appendChild(tm);

  if (mine) line.append(meta, bubble);
  else line.append(bubble, meta);
  col.appendChild(line);
  row.appendChild(col);
  return row;
}

function sendPayload(extra) {
  const payload = current.type === 'group' ? { groupId: current.id, ...extra } : { to: current.id, ...extra };
  socket.emit('message:send', payload, (res) => {
    if (res && res.error) alert(res.error);
  });
}

$('#compose').onsubmit = (e) => {
  e.preventDefault();
  const text = $('#msg-input').value.trim();
  if (!text || !current) return;
  sendPayload({ text });
  $('#msg-input').value = '';
};

// 파일 보내기 (2MB 이하, 이미지 / PDF / 텍스트)
$('#attach').onchange = async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file || !current) return;
  if (file.size > 2 * 1024 * 1024) return alert('2MB 이하 파일만 보낼 수 있습니다');
  try {
    const r = await fetch('/api/files', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': file.type || 'application/octet-stream',
        'X-File-Name': encodeURIComponent(file.name),
      },
      body: file,
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || '파일 업로드에 실패했습니다');
    const text = $('#msg-input').value.trim();
    sendPayload({ fileId: j.id, text });
    $('#msg-input').value = '';
  } catch (err) {
    alert(err.message);
  }
};

// 새 메시지 수신: 열린 대화면 말풍선 추가, 아니면 대화 목록과 뱃지 갱신
function onMessage(m) {
  const isGroupMsg = !!m.group_id;
  const relevant = current && (isGroupMsg
    ? current.type === 'group' && current.id === m.group_id
    : current.type === 'dm' && (m.sender_id === current.id || m.recipient_id === current.id));

  if (relevant) {
    appendMsg(m);
    if (!isGroupMsg && m.sender_id === current.id) socket.emit('read:dm', { userId: current.id });
  }

  const other = isGroupMsg ? null : (m.sender_id === me.id ? m.recipient_id : m.sender_id);
  const c = chats.find((x) => (isGroupMsg ? x.type === 'group' && x.id === m.group_id : x.type === 'dm' && x.id === other));
  if (c) {
    c.last = { text: m.text, kind: m.kind, created_at: m.created_at, sender_name: m.sender_name };
    if (!isGroupMsg && m.sender_id !== me.id && !relevant) c.unread = (c.unread || 0) + 1;
    renderList();
  }
}

// 상대가 내 메시지를 읽으면 "1" 표시를 지웁니다
function onRead({ by, ids }) {
  if (!current || current.type !== 'dm' || current.id !== by) return;
  const now = new Date().toISOString();
  for (const m of chatMsgs) if (ids.includes(m.id)) m.read_at = now;
  for (const id of ids) {
    const r = document.querySelector('.msg-row[data-id="' + id + '"] .read');
    if (r) r.textContent = '';
  }
}

$('#btn-block').onclick = async () => {
  if (!current || !confirm(current.name + '님을 차단할까요?')) return;
  try {
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ userId: current.id }) });
    current = null;
    setChatOpen(false);
    $('#chat-box').innerHTML = '';
    await loadList();
  } catch (err) {
    alert(err.message);
  }
};

$('#btn-report').onclick = async () => {
  if (!current) return;
  const reason = prompt('신고 사유를 입력하세요 (500자 이내)');
  if (!reason) return;
  try {
    await api('/api/reports', { method: 'POST', body: JSON.stringify({ userId: current.id, reason }) });
    alert('신고가 접수되었습니다.');
  } catch (err) {
    alert(err.message);
  }
};

// 그룹 멤버 초대 (친구 아이디로)
$('#btn-gadd').onclick = async () => {
  if (!current || current.type !== 'group') return;
  const username = prompt('초대할 친구의 아이디를 입력하세요');
  if (!username) return;
  const f = friends.find((x) => x.username === username.trim().toLowerCase());
  if (!f) return alert('친구 목록에서 찾을 수 없습니다. 친구만 초대할 수 있습니다.');
  try {
    await api('/api/groups/' + current.id + '/members', { method: 'POST', body: JSON.stringify({ userId: f.id }) });
    await loadList();
    alert(f.name + '님을 초대했습니다.');
  } catch (err) {
    alert(err.message);
  }
};

$('#btn-gleave').onclick = async () => {
  if (!current || current.type !== 'group' || !confirm('이 그룹을 나갈까요?')) return;
  try {
    await api('/api/groups/' + current.id + '/leave', { method: 'POST' });
    current = null;
    setChatOpen(false);
    $('#chat-box').innerHTML = '';
    await loadList();
  } catch (err) {
    alert(err.message);
  }
};

// ---------- 푸시 알림 ----------
function urlB64ToUint8(b64) {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

// silent=true: 이미 허용된 경우에만 구독 (화면 시작 시). false: 권한 요청 포함 (버튼 클릭 시)
async function enablePush(silent) {
  const supported = 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
  if (!supported) {
    if (!silent) alert('이 브라우저에서는 알림을 쓸 수 없습니다.\n아이폰은 사파리에서 "홈 화면에 추가" 후 앱을 열어 주세요.');
    return false;
  }
  if (Notification.permission === 'default' && !silent) {
    const p = await Notification.requestPermission();
    if (p !== 'granted') { alert('알림이 허용되지 않았습니다.'); return false; }
  }
  if (Notification.permission !== 'granted') return false;

  const reg = await navigator.serviceWorker.ready;
  const { publicKey } = await api('/api/push/key');
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8(publicKey) });
  }
  await api('/api/push/subscribe', { method: 'POST', body: JSON.stringify({ subscription: sub.toJSON() }) });
  if (!silent) alert('알림이 켜졌습니다. 앱을 닫아도 새 메시지 알림을 받을 수 있습니다.');
  return true;
}

async function disablePush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return;
  await api('/api/push/unsubscribe', { method: 'POST', body: JSON.stringify({ endpoint: sub.endpoint }) }).catch(() => {});
  await sub.unsubscribe();
}

$('#btn-notify').onclick = () => enablePush(false).catch((err) => alert(err.message));

async function logout() {
  await disablePush().catch(() => {});
  localStorage.removeItem('token');
  token = null;
  if (socket) socket.disconnect();
  location.reload();
}
$('#logout').onclick = logout;

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

if (token) start();
else showView('auth');

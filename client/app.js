const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token');
let me = null, socket = null, current = null, oldestId = null;
let pendingEmail = '', resetEmail = '';
let friends = [], groups = [], unread = {};
const blobCache = new Map();

// 카카오 로그인 후 주소 뒤에 붙은 토큰을 저장하고 주소를 정리합니다.
const tokenMatch = location.hash.match(/token=([^&]+)/);
if (tokenMatch) {
  token = tokenMatch[1];
  localStorage.setItem('token', token);
  history.replaceState(null, '', location.pathname);
}

const VIEWS = ['auth', 'verify', 'main', 'reset', 'pw', 'profile', 'blocks', 'group', 'admin'];
function showView(name) {
  for (const v of VIEWS) $('#view-' + v).hidden = v !== name;
}

// 하단 탭 (친구 / 대화 / 설정)
let activeTab = 'friends';
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
  $('#me').textContent = me.name + ' (@' + me.username + ')';
  $('#me-status').textContent = me.status_msg || '상태 메시지가 없습니다';
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
    l.append(c, ' ' + f.name + '  @' + f.username);
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

// ---------- 메인: 목록 ----------
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
  await loadUnread();
  connectSocket();
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

async function loadList() {
  [friends, groups] = await Promise.all([api('/api/friends'), api('/api/groups')]);
  renderFriends();
  renderList();
}

async function loadUnread() {
  const rows = await api('/api/unread');
  unread = {};
  for (const r of rows) unread[r.sender_id] = r.count;
  renderList();
}

// 친구 탭: 친구 목록
function renderFriends() {
  const q = $('#fsearch').value.trim().toLowerCase();
  const ul = $('#friends');
  ul.innerHTML = '';
  for (const f of friends) {
    if (q && !(f.name + f.username).toLowerCase().includes(q)) continue;
    ul.appendChild(listItem({ type: 'dm', id: f.id, name: f.name, username: f.username }, 0));
  }
  if (!ul.children.length) ul.innerHTML = '<li class="muted">친구가 없습니다. 위에서 아이디로 친구를 추가하세요.</li>';
}

// 대화 탭: 그룹 + 친구 대화 (안 읽은 메시지가 많은 순)
function renderList() {
  const q = $('#search').value.trim().toLowerCase();
  const ul = $('#list');
  ul.innerHTML = '';
  const match = (s) => !q || s.toLowerCase().includes(q);
  for (const g of groups) {
    if (!match(g.name)) continue;
    const t = { type: 'group', id: g.id, name: g.name, count: g.members ? g.members.length : 0 };
    ul.appendChild(listItem(t, 0));
  }
  const dms = friends
    .filter((f) => match(f.name + f.username))
    .sort((a, b) => (unread[b.id] || 0) - (unread[a.id] || 0));
  for (const f of dms) {
    ul.appendChild(listItem({ type: 'dm', id: f.id, name: f.name, username: f.username }, unread[f.id] || 0));
  }
  if (!ul.children.length) ul.innerHTML = '<li class="muted">대화가 없습니다. 친구 탭에서 친구를 추가하세요.</li>';

  // 하단 탭의 "대화" 뱃지: 안 읽은 메시지 총합
  const total = Object.values(unread).reduce((a, b) => a + b, 0);
  const badge = $('#chat-badge');
  badge.hidden = !total;
  badge.textContent = total > 99 ? '99+' : String(total);
}

function listItem(t, badge) {
  const li = document.createElement('li');
  if (current && current.type === t.type && current.id === t.id) li.classList.add('on');
  const label = document.createElement('span');
  label.textContent = t.type === 'group' ? '👥 ' + t.name + ' (' + t.count + '명)' : t.name + '  @' + t.username;
  li.appendChild(label);
  if (badge) {
    const b = document.createElement('b');
    b.className = 'badge';
    b.textContent = badge;
    li.appendChild(b);
  }
  li.onclick = () => openChat(t);
  return li;
}

$('#search').oninput = renderList;
$('#fsearch').oninput = renderFriends;

// 받은 친구 요청 (수락 / 거절)
async function loadRequests() {
  const list = await api('/api/friends/requests');
  const ul = $('#requests');
  ul.innerHTML = '';
  $('#req-box').hidden = list.length === 0;
  for (const r of list) {
    const li = document.createElement('li');
    li.textContent = r.name + '  @' + r.username + ' ';
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

// ---------- 채팅 ----------
function isCurrent(t) {
  return current && current.type === t.type && current.id === t.id;
}

async function openChat(t) {
  current = t;
  oldestId = null;
  setChatOpen(true);
  $('#chat-title').textContent = t.type === 'group' ? '👥 ' + t.name : t.name + '  @' + t.username;
  $('#dm-actions').hidden = t.type !== 'dm';
  $('#group-actions').hidden = t.type !== 'group';
  $('#compose').hidden = false;
  $('#chat-box').innerHTML = '';
  await loadMessages(true);
  if (t.type === 'dm') {
    socket.emit('read:dm', { userId: t.id });
    unread[t.id] = 0;
    renderList();
  } else {
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
  const box = $('#chat-box');
  const frag = document.createDocumentFragment();
  for (const m of rows) frag.appendChild(makeMsg(m));
  if (rows.length) oldestId = rows[0].id;
  $('#more').hidden = rows.length < 50;
  if (initial) {
    box.innerHTML = '';
    box.appendChild(frag);
    box.scrollTop = box.scrollHeight;
  } else {
    const prev = box.scrollHeight;
    box.insertBefore(frag, box.firstChild);
    box.scrollTop = box.scrollHeight - prev;
  }
}

$('#more').onclick = () => loadMessages(false);

function makeMsg(m) {
  const mine = m.sender_id === me.id;
  const row = document.createElement('div');
  row.className = 'msg-row ' + (mine ? 'me' : 'them');
  row.dataset.id = m.id;

  if (!mine && current && current.type === 'group' && m.sender_name) {
    const who = document.createElement('div');
    who.className = 'sender';
    who.textContent = m.sender_name;
    row.appendChild(who);
  }

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
  row.appendChild(bubble);

  if (mine && current && current.type === 'dm') {
    const r = document.createElement('div');
    r.className = 'read';
    r.textContent = m.read_at ? '읽음' : '';
    row.appendChild(r);
  }
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

function onMessage(m) {
  const isGroupMsg = !!m.group_id;
  const relevant = current && (isGroupMsg
    ? current.type === 'group' && current.id === m.group_id
    : current.type === 'dm' && (m.sender_id === current.id || m.recipient_id === current.id));

  if (relevant) {
    const box = $('#chat-box');
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    box.appendChild(makeMsg(m));
    if (atBottom || m.sender_id === me.id) box.scrollTop = box.scrollHeight;
    if (!isGroupMsg && m.sender_id === current.id) socket.emit('read:dm', { userId: current.id });
  } else if (!isGroupMsg && m.recipient_id === me.id) {
    unread[m.sender_id] = (unread[m.sender_id] || 0) + 1;
    renderList();
  }
}

// 상대가 내 메시지를 읽으면 "읽음" 표시
function onRead({ by, ids }) {
  if (!current || current.type !== 'dm' || current.id !== by) return;
  for (const id of ids) {
    const r = document.querySelector('.msg-row[data-id="' + id + '"] .read');
    if (r) r.textContent = '읽음';
  }
}

$('#btn-block').onclick = async () => {
  if (!current || !confirm(current.name + '님을 차단할까요?')) return;
  try {
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ userId: current.id }) });
    current = null;
    $('#chat-box').innerHTML = '';
    $('#chat-title').textContent = '차단되었습니다';
    $('#dm-actions').hidden = true;
    $('#group-actions').hidden = true;
    $('#compose').hidden = true;
    $('#more').hidden = true;
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
    $('#chat-title').textContent = '대화를 선택하세요';
    $('#group-actions').hidden = true;
    $('#compose').hidden = true;
    $('#more').hidden = true;
    await loadList();
  } catch (err) {
    alert(err.message);
  }
};

function logout() {
  localStorage.removeItem('token');
  token = null;
  if (socket) socket.disconnect();
  location.reload();
}
$('#logout').onclick = logout;

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');

if (token) start();
else showView('auth');

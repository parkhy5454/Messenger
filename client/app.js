const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token');
let me = null, socket = null, current = null, pendingEmail = '';

// 카카오 로그인 후 주소 뒤에 붙은 토큰을 저장하고 주소를 정리합니다.
const tokenMatch = location.hash.match(/token=([^&]+)/);
if (tokenMatch) {
  token = tokenMatch[1];
  localStorage.setItem('token', token);
  history.replaceState(null, '', location.pathname);
}

function showView(name) {
  for (const v of ['auth', 'verify', 'main']) $('#view-' + v).hidden = v !== name;
}

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const r = await fetch(path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || '요청에 실패했습니다 (' + r.status + ')');
  return j;
}

// 탭 전환
$('#tab-login').onclick = () => { $('#login-form').hidden = false; $('#signup-form').hidden = true; setTab('login'); };
$('#tab-signup').onclick = () => { $('#login-form').hidden = true; $('#signup-form').hidden = false; setTab('signup'); };
function setTab(t) {
  $('#tab-login').classList.toggle('active', t === 'login');
  $('#tab-signup').classList.toggle('active', t === 'signup');
  $('#auth-msg').textContent = '';
}

// 로그인
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

// 회원가입 → 인증 코드 입력
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

// 메인 화면 시작
async function start() {
  try {
    me = await api('/api/me');
  } catch {
    return logout();
  }
  showView('main');
  $('#me').textContent = me.name + ' (@' + me.username + ')';
  await loadFriends();

  if (socket) socket.disconnect();
  socket = io({ auth: { token } });
  socket.on('message:new', onMessage);
  socket.on('connect_error', (err) => {
    if (err.message === 'unauthorized') logout();
  });
}

async function loadFriends() {
  const list = await api('/api/friends');
  const ul = $('#friends');
  ul.innerHTML = '';
  for (const f of list) {
    const li = document.createElement('li');
    li.textContent = f.name + '  @' + f.username;
    if (current && current.id === f.id) li.classList.add('on');
    li.onclick = () => openChat(f);
    ul.appendChild(li);
  }
}

async function openChat(f) {
  current = f;
  $('#chat-title').textContent = f.name + '  @' + f.username;
  $('#chat-actions').hidden = false;
  $('#compose').hidden = false;
  $('#chat-box').innerHTML = '';
  const msgs = await api('/api/messages/' + f.id);
  msgs.forEach(addMsg);
  await loadFriends();
  $('#msg-input').focus();
}

function addMsg(m) {
  const box = $('#chat-box');
  const d = document.createElement('div');
  d.className = 'msg ' + (m.sender_id === me.id ? 'me' : 'them');
  d.textContent = m.text;
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
}

function onMessage(m) {
  if (!current) return;
  if (m.sender_id === current.id || m.recipient_id === current.id) addMsg(m);
}

$('#compose').onsubmit = (e) => {
  e.preventDefault();
  const text = $('#msg-input').value.trim();
  if (!text || !current) return;
  socket.emit('message:send', { to: current.id, text }, (res) => {
    if (res && res.error) alert(res.error);
  });
  $('#msg-input').value = '';
};

$('#add-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/friends', { method: 'POST', body: JSON.stringify({ username: $('#add-input').value.trim() }) });
    $('#add-input').value = '';
    await loadFriends();
  } catch (err) {
    alert(err.message);
  }
};

$('#btn-block').onclick = async () => {
  if (!current || !confirm(current.name + '님을 차단할까요?')) return;
  try {
    await api('/api/blocks', { method: 'POST', body: JSON.stringify({ userId: current.id }) });
    current = null;
    $('#chat-box').innerHTML = '';
    $('#chat-title').textContent = '차단되었습니다';
    $('#chat-actions').hidden = true;
    $('#compose').hidden = true;
    await loadFriends();
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

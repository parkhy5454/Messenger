const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token');
let me = null, socket = null, current = null, oldestId = null, chatMsgs = [];
let pendingEmail = '', resetEmail = '';
let friends = [], chats = [];
let pendingPassword = null;
let activeTab = 'friends';
const blobCache = new Map();

// 카카오 로그인 후 주소 뒤에 붙은 토큰을 저장하고 주소를 정리합니다.
const inviteMatch = location.hash.match(/invite=([a-f0-9]+)/);
if (inviteMatch) {
  localStorage.setItem('pendingInvite', inviteMatch[1]);
  history.replaceState(null, '', location.pathname);
}
const tokenMatch = location.hash.match(/token=([^&]+)/);
if (tokenMatch) {
  token = tokenMatch[1];
  localStorage.setItem('token', token);
  history.replaceState(null, '', location.pathname);
}

// ---------- 공통 유틸 ----------
const VIEWS = ['auth', 'verify', 'main', 'reset', 'pw', 'profile', 'blocks', 'group', 'admin', 'unlock', 'security', 'scheduled', 'profiles', 'ai', 'bots', 'plan', 'quiet', 'gboard'];
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

// ---------- 종단간 암호화 (1:1 대화) ----------
// 내 키는 이 기기의 IndexedDB에 저장하고, 서버에는 비밀번호로 감싼 개인키만 둡니다.
const INLINE_IMG = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
let myKey = null;            // { privKey, pubB64 }
const peerKeys = new Map();  // 상대 id -> 공유 AES 키

// 반환: 'ready' | 'locked'(비밀번호 입력 필요) | 'missing'(이 기기에 키 없음)
async function setupKeys(password) {
  const local = await E2EE.loadLocal(me.id);
  const remote = await api('/api/e2ee/me');
  if (local && remote.pubkey === local.pub) {
    myKey = { privKey: local.priv, pubB64: local.pub, pkcs8: local.pkcs8 };
    return 'ready';
  }
  if (remote.pubkey) {
    if (!remote.enc_privkey) { myKey = null; return 'missing'; }
    if (!password) return 'locked';
    let pkcs8;
    try { pkcs8 = await E2EE.unlockPkcs8(password, remote.enc_privkey); }
    catch { throw new Error('비밀번호가 올바르지 않습니다'); }
    await E2EE.saveLocal(me.id, pkcs8, remote.pubkey);
    myKey = { privKey: await E2EE.importPrivate(pkcs8), pubB64: remote.pubkey, pkcs8 };
    peerKeys.clear();
    return 'ready';
  }
  // 서버에 키가 없으면 새로 만듭니다 (비밀번호가 없으면 서버 백업 없이 이 기기에만 저장)
  const id = await E2EE.createIdentity(password || null);
  await api('/api/e2ee/setup', { method: 'POST', body: JSON.stringify({ pubkey: id.pubB64, encPrivkey: id.blob }) });
  await E2EE.saveLocal(me.id, id.pkcs8, id.pubB64);
  myKey = { privKey: id.privKey, pubB64: id.pubB64, pkcs8: id.pkcs8 };
  peerKeys.clear();
  return 'ready';
}

// 상대와의 공유 키 (공개키를 받아 한 번 만들고 캐시)
async function peerKey(peerId) {
  if (!myKey) throw new Error('이 기기에서 암호화 키를 찾을 수 없습니다. 처음 설정한 기기에서 사용하세요');
  if (!peerKeys.has(peerId)) {
    const { pubkey } = await api('/api/users/' + peerId + '/pubkey');
    if (!pubkey) throw new Error('상대방이 아직 암호화 키를 만들지 않았습니다. 상대가 한 번 로그인하면 보낼 수 있습니다');
    peerKeys.set(peerId, await E2EE.sharedKey(myKey.privKey, pubkey));
  }
  return peerKeys.get(peerId);
}

function peerOf(m) { return m.sender_id === me.id ? m.recipient_id : m.sender_id; }

// ----- 그룹 키 -----
// 세대(epoch)별 그룹 키를 이 기기에 저장합니다 (IndexedDB, 이름: g<그룹>:<세대>)
const groupKeys = new Map(); // 'gid:epoch' -> CryptoKey
async function groupRaw(gid, epoch) {
  const b64 = await E2EE.loadKV('g' + gid + ':' + epoch);
  return b64 ? E2EE.fromB64(b64) : null;
}
async function groupKey(gid, epoch) {
  const id = gid + ':' + epoch;
  if (!groupKeys.has(id)) {
    const raw = await groupRaw(gid, epoch);
    if (!raw) return null;
    groupKeys.set(id, await E2EE.importRawKey(raw));
  }
  return groupKeys.get(id);
}
async function saveGroupRaw(gid, epoch, raw) {
  await E2EE.saveKV('g' + gid + ':' + epoch, E2EE.toB64(raw));
  groupKeys.delete(gid + ':' + epoch);
}

// 서버와 키를 맞춥니다: 받은 키 풀기, 필요하면 키 교체, 내가 가진 키를 키 없는 멤버에게 나눠주기
async function syncGroupKeys(gid) {
  let st = await api('/api/groups/' + gid + '/keys');
  if (!st.enc) return st;
  if (!myKey) throw new Error('이 기기에서 암호화 키를 찾을 수 없습니다');
  const pub = new Map(st.members.map((m) => [m.id, m.pubkey]));
  for (const row of st.keys) {
    if (await groupRaw(gid, row.epoch)) continue;
    const fromPub = pub.get(row.from_user);
    if (!fromPub) continue;
    const raw = await E2EE.unwrapRaw(await E2EE.sharedKey(myKey.privKey, fromPub), row.wrapped);
    await saveGroupRaw(gid, row.epoch, raw);
  }
  if (st.needsRotate) {
    const r = await api('/api/groups/' + gid + '/rotate', { method: 'POST' });
    if (r.rotated) await saveGroupRaw(gid, r.epoch, E2EE.genRaw());
    st = await api('/api/groups/' + gid + '/keys');
  }
  const have = new Set(st.have.map((h) => h.user_id + ':' + h.epoch));
  const out = [];
  for (const m of st.members) {
    if (!m.pubkey) continue;
    const shared = await E2EE.sharedKey(myKey.privKey, m.pubkey);
    for (let e = 0; e <= st.epoch; e++) {
      if (have.has(m.id + ':' + e)) continue;
      const raw = await groupRaw(gid, e);
      if (!raw) continue;
      out.push({ userId: m.id, epoch: e, wrapped: E2EE.wrapRaw(shared, raw) });
    }
  }
  for (const o of out) o.wrapped = await o.wrapped;
  if (out.length) await api('/api/groups/' + gid + '/keys', { method: 'POST', body: JSON.stringify({ keys: out }) });
  return st;
}

// 보낼 때 쓸 키: 1:1은 상대와의 공유 키, 암호화된 그룹은 현재 세대 키, 평문 그룹은 null
async function sendKey() {
  if (current.type === 'dm') return { key: await peerKey(current.id), epoch: null };
  const st = await syncGroupKeys(current.id);
  if (!st.enc) return null;
  const key = await groupKey(current.id, st.epoch);
  if (!key) throw new Error('그룹 암호화 키를 아직 받지 못했습니다. 잠시 후 다시 시도하세요');
  return { key, epoch: st.epoch };
}

// 메시지를 풀 때 쓸 키 (그룹은 키가 없으면 한 번 동기화 후 다시 찾습니다)
async function keyForMsg(m, peerId) {
  if (m.group_id) {
    let k = await groupKey(m.group_id, m.key_epoch);
    if (!k) { await syncGroupKeys(m.group_id); k = await groupKey(m.group_id, m.key_epoch); }
    if (!k) throw new Error('키 없음');
    return k;
  }
  return peerKey(peerId || peerOf(m));
}

// 암호화된 1:1 메시지를 화면에 쓸 수 있는 모양(text, kind, file_*)으로 바꿉니다
async function decryptMsg(m, peerId) {
  if (!m || !m.enc) return m;
  try {
    const k = await keyForMsg(m, peerId);
    const p = await E2EE.open(k, m.text);
    const f = p.f || null;
    return {
      ...m,
      text: p.t || '',
      kind: f ? (INLINE_IMG.includes(f.mime) ? 'image' : 'file') : 'text',
      file_name: f ? f.name : null,
      file_mime: f ? f.mime : null,
      file_iv: f ? f.iv : null,
    };
  } catch {
    return { ...m, text: '[복호화할 수 없는 메시지]', kind: 'text', file_id: null };
  }
}

// 첨부 파일: 암호화된 1:1 파일은 받아서 복호화한 뒤 blob 주소로 씁니다
async function fileUrl(m) {
  if (!m.enc) return loadBlob(m.file_id);
  const key = 'enc' + m.file_id;
  if (!blobCache.has(key)) {
    const r = await fetch('/api/files/' + m.file_id, { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) throw new Error('파일을 불러올 수 없습니다');
    const k = await keyForMsg(m);
    const plain = await E2EE.openBytes(k, m.file_iv, await r.arrayBuffer());
    blobCache.set(key, URL.createObjectURL(new Blob([plain], { type: m.file_mime || 'application/octet-stream' })));
  }
  return blobCache.get(key);
}

$('#unlock-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await setupKeys($('#ul-pass').value);
    $('#ul-pass').value = '';
    await enterMain();
  } catch (err) {
    $('#unlock-msg').textContent = err.message;
  }
};
$('#unlock-logout').onclick = logout;
$('#unlock-other').onclick = () => requestApproval().catch((err) => {
  $('#unlock-msg').textContent = err.message;
  $('#unlock-code').textContent = '';
});

// 새 기기: 이미 로그인된 다른 기기의 승인을 받아 개인키를 가져옵니다 (비밀번호 입력 없음)
async function requestApproval() {
  $('#unlock-msg').textContent = '';
  const eph = await E2EE.genEphemeral();
  const r = await api('/api/devices/request', { method: 'POST', body: JSON.stringify({ pubkey: eph.pubB64 }) });
  $('#unlock-code').textContent = '확인 번호: ' + eph.code + ' (다른 기기에 같은 번호가 보이면 승인하세요)';
  const remote = await api('/api/e2ee/me');
  const until = Date.now() + 5 * 60 * 1000;
  while (Date.now() < until) {
    await new Promise((res) => setTimeout(res, 2000));
    const s = await api('/api/devices/request/' + r.id);
    if (s.status === 'denied') throw new Error('다른 기기에서 승인이 거절되었습니다');
    if (s.status === 'expired') break;
    if (s.status === 'approved') {
      const p = JSON.parse(s.payload);
      if (p.pub !== remote.pubkey) throw new Error('키가 일치하지 않습니다. 다시 시도하세요');
      const K = await E2EE.sharedKey(eph.privKey, p.pub);
      const pkcs8 = E2EE.fromB64((await E2EE.open(K, p.ct)).pkcs8);
      await E2EE.saveLocal(me.id, pkcs8, p.pub);
      myKey = { privKey: await E2EE.importPrivate(pkcs8), pubB64: p.pub, pkcs8 };
      peerKeys.clear();
      $('#unlock-code').textContent = '';
      return enterMain();
    }
  }
  throw new Error('승인 시간이 지났습니다. 다시 시도하세요');
}

// 기존 기기: 새 기기 요청이 오면 확인 번호를 보여 주고 승인하거나 거절합니다
async function approveDevice(req) {
  if (!myKey || !myKey.pkcs8) {
    return alert('이 기기에서는 새 기기를 승인할 수 없습니다. 비밀번호로 한 번 다시 로그인한 뒤 시도하세요.');
  }
  const code = await E2EE.codeOf(req.pubkey);
  const ok = confirm('새 기기에서 로그인 요청이 왔습니다.\n\n새 기기에 표시된 확인 번호가 [' + code + '] 인지 확인하세요.\n\n본인이 로그인한 것이라면 승인하세요.');
  if (!ok) return api('/api/devices/request/' + req.id + '/deny', { method: 'POST' });
  const K = await E2EE.sharedKey(myKey.privKey, req.pubkey);
  const ct = await E2EE.seal(K, { pkcs8: E2EE.toB64(myKey.pkcs8) });
  await api('/api/devices/request/' + req.id + '/approve', {
    method: 'POST',
    body: JSON.stringify({ payload: JSON.stringify({ pub: myKey.pubB64, ct }) }),
  });
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
// 프로필 사진 (있으면 사진, 없으면 이름 글자 아바타). 사진은 인증 헤더로 받아서 blob 주소로 씁니다
const avatarCache = new Map();
async function avatarUrl(uid) {
  if (!avatarCache.has(uid)) {
    const r = await fetch('/api/users/' + uid + '/avatar', { headers: { Authorization: 'Bearer ' + token } });
    if (!r.ok) return null;
    avatarCache.set(uid, URL.createObjectURL(await r.blob()));
  }
  return avatarCache.get(uid);
}
function avatarNodeFor(uid, name, cls) {
  const el = avatarEl(name, cls);
  const info = !uid ? null : (uid === me.id ? me : friends.find((f) => f.id === uid));
  if (info && info.has_photo) {
    avatarUrl(uid).then((url) => {
      if (!url) return;
      el.textContent = '';
      el.style.background = 'none';
      const img = document.createElement('img');
      img.className = 'av-img';
      img.alt = '';
      img.src = url;
      el.appendChild(img);
    }).catch(() => {});
  }
  return el;
}

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
  av.appendChild(avatarNodeFor(me.id, me.name, 'lg'));
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

let pendingOtp = null;
$('#login-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    if (pendingOtp) {
      const r = await api('/api/auth/otp', { method: 'POST', body: JSON.stringify({ pending: pendingOtp, code: $('#li-otp').value.trim() }) });
      pendingOtp = null;
      $('#otp-row').hidden = true;
      token = r.token;
      localStorage.setItem('token', token);
      pendingPassword = $('#li-pass').value;
      await start();
      return;
    }
    const r = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: $('#li-user').value, password: $('#li-pass').value }),
    });
    if (r.otp) {
      pendingOtp = r.pending;
      $('#otp-row').hidden = false;
      $('#li-otp').focus();
      $('#auth-msg').textContent = '인증 앱의 6자리 코드를 입력하세요';
      return;
    }
    token = r.token;
    localStorage.setItem('token', token);
    pendingPassword = $('#li-pass').value;
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
    const cur = $('#pw-cur').value, next = $('#pw-new').value;
    const ek = await api('/api/e2ee/me');
    let encPrivkey;
    if (ek.enc_privkey) {
      encPrivkey = await E2EE.rewrap(cur, ek.enc_privkey, next).catch(() => {
        throw new Error('현재 비밀번호가 올바르지 않습니다');
      });
    }
    await api('/api/me/password', {
      method: 'POST',
      body: JSON.stringify({ current: cur, next, encPrivkey }),
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
  loadStats().catch(() => {});
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
    const body = { name: $('#gr-name').value.trim(), memberIds: ids, purpose: $('#gr-purpose').value };
    const pubs = await Promise.all([me.id, ...ids].map(async (uid) => {
      if (uid === me.id) return { uid, pubkey: myKey ? myKey.pubB64 : null };
      return { uid, pubkey: (await api('/api/users/' + uid + '/pubkey')).pubkey };
    }));
    if (myKey && pubs.every((p) => p.pubkey)) {
      const raw = E2EE.genRaw();
      body.enc = true;
      body.keys = [];
      for (const p of pubs) {
        const shared = await E2EE.sharedKey(myKey.privKey, p.pubkey);
        body.keys.push({ userId: p.uid, wrapped: await E2EE.wrapRaw(shared, raw) });
      }
      const created = await api('/api/groups', { method: 'POST', body: JSON.stringify(body) });
      await saveGroupRaw(created.id, 0, raw);
      $('#gr-msg').textContent = '';
    } else {
      await api('/api/groups', { method: 'POST', body: JSON.stringify(body) });
      alert('일부 친구가 암호화 키를 아직 만들지 않아 일반 그룹으로 만들었습니다.');
    }
    openMain('chats');
    await loadList();
  } catch (err) {
    $('#gr-msg').textContent = err.message;
  }
};

// ---------- 메시지 메뉴 / 답장 / 수정 / 삭제 / 전달 ----------
let replyTo = null, editing = null;

function quoteEl(m) {
  const p = chatMsgs.find((x) => x.id === m.reply_to);
  const d = document.createElement('div');
  d.className = 'quote';
  d.textContent = !p ? '원본 메시지' : p.deleted ? '삭제된 메시지입니다' : p.kind === 'image' ? '사진' : p.kind === 'file' ? '파일' : (p.text || '');
  return d;
}

function openMsgMenu(m) {
  if (m.deleted) return;
  const mine = m.sender_id === me.id;
  const items = [['답장', () => setReply(m)], ['전달', () => forwardMsg(m)], ['반응', () => openSheet(REACTION_EMOJI.map((e) => [e, () => toggleReaction(m, e)]))]];
  if (mine && !m.file_id) items.push(['수정', () => setEdit(m)]);
  if (mine) items.push(['삭제', () => deleteMsg(m)]);
  const box = $('#msg-menu-box');
  box.innerHTML = '';
  for (const item of items) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ghost wide-btn';
    b.textContent = item[0];
    b.onclick = () => { closeMsgMenu(); item[1](); };
    box.appendChild(b);
  }
  $('#msg-menu').hidden = false;
}
function closeMsgMenu() { $('#msg-menu').hidden = true; }
$('#msg-menu').onclick = (e) => { if (e.target.id === 'msg-menu') closeMsgMenu(); };
$('#msg-menu-cancel').onclick = closeMsgMenu;

function showComposeBar(text) {
  $('#compose-bar-text').textContent = text;
  $('#compose-bar').hidden = false;
}
function clearCompose() {
  replyTo = null;
  editing = null;
  $('#compose-bar').hidden = true;
}
$('#compose-bar-x').onclick = () => { if (editing) $('#msg-input').value = ''; clearCompose(); };

function setReply(m) {
  editing = null;
  replyTo = m;
  const preview = m.kind === 'image' ? '사진' : m.kind === 'file' ? '파일' : (m.text || '');
  showComposeBar('답장: ' + preview.slice(0, 40));
  $('#msg-input').focus();
}
function setEdit(m) {
  replyTo = null;
  editing = m;
  $('#msg-input').value = m.text || '';
  showComposeBar('메시지 수정 중');
  $('#msg-input').focus();
}

// 수정: 암호화 메시지는 같은 키로 다시 암호화해서 보냅니다
async function submitEdit(m, text) {
  try {
    let body = text;
    if (m.enc) {
      const k = await keyForMsg(m);
      const f = m.file_id ? { name: m.file_name, mime: m.file_mime, iv: m.file_iv } : null;
      body = await E2EE.seal(k, { t: text, f });
    }
    socket.emit('message:edit', { id: m.id, text: body, enc: !!m.enc }, (res) => {
      if (res && res.error) alert(res.error);
    });
  } catch (err) {
    alert(err.message);
  }
}

function deleteMsg(m) {
  if (!confirm('이 메시지를 삭제할까요? 상대방 화면에서도 지워집니다.')) return;
  socket.emit('message:delete', { id: m.id }, (res) => {
    if (res && res.error) alert(res.error);
  });
}

// 전달: 텍스트 메시지만 (파일은 제외). 대화 목록에 있는 친구 아이디나 그룹 이름으로 찾습니다
async function forwardMsg(m) {
  if (m.file_id) return alert('파일은 전달할 수 없습니다. 텍스트 메시지만 전달할 수 있습니다.');
  const q = (prompt('전달할 친구 아이디 또는 그룹 이름을 입력하세요') || '').trim();
  if (!q) return;
  const target = chats.find((c) => (c.type === 'group' ? c.name === q : c.username === q.toLowerCase()));
  if (!target) return alert('대화 목록에서 찾을 수 없습니다. 친구나 그룹 대화가 있어야 전달할 수 있습니다.');
  const prev = current;
  current = target;
  try {
    await sendPayload({ text: m.text || '' });
  } finally {
    current = prev;
  }
}

// 수정·삭제 알림 수신: 열려 있는 대화만 갱신
async function onUpdated(u) {
  const old = chatMsgs.find((x) => x.id === u.id);
  if (!old) return;
  Object.assign(old, await decryptMsg({ ...old, text: u.text, enc: u.enc, edited_at: u.edited_at }));
  renderChat('keep');
}
function onDeleted(d) {
  const old = chatMsgs.find((x) => x.id === d.id);
  if (!old) return;
  Object.assign(old, { deleted: true, text: '', file_id: null });
  renderChat('keep');
}

// ---------- 자동 삭제 / 한 번만 보기 ----------
function openSheet(items) {
  const box = $('#msg-menu-box');
  box.innerHTML = '';
  for (const item of items) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ghost wide-btn';
    b.textContent = item[0];
    b.onclick = () => { closeMsgMenu(); item[1](); };
    box.appendChild(b);
  }
  $('#msg-menu').hidden = false;
}

const TTL_LABELS = { 0: '끄기', 60: '1분', 3600: '1시간', 86400: '1일', 604800: '1주일' };
$('#btn-ttl').onclick = () => {
  if (!current || current.type !== 'dm') return;
  openSheet(Object.keys(TTL_LABELS).map((sec) => ['자동 삭제: ' + TTL_LABELS[sec], () => setTtl(Number(sec))]));
};
async function setTtl(sec) {
  try {
    await api('/api/prefs/ttl/' + current.id, { method: 'POST', body: JSON.stringify({ ttl: sec }) });
    alert('자동 삭제: ' + TTL_LABELS[sec] + ' (이 대화의 새 메시지부터 적용됩니다)');
  } catch (err) {
    alert(err.message);
  }
}

// 한 번만 보기: 사진을 전체 화면으로 한 번 보여 주고, 닫으면 서버에서 사진을 지웁니다
async function openViewOnce(m) {
  try {
    const url = await fileUrl(m);
    const ov = document.createElement('div');
    ov.className = 'viewer';
    const img = document.createElement('img');
    img.src = url;
    img.alt = '';
    ov.appendChild(img);
    ov.onclick = () => { ov.remove(); markViewed(m); };
    document.body.appendChild(ov);
  } catch (err) {
    alert(err.message);
  }
}
async function markViewed(m) {
  await api('/api/messages/' + m.id + '/view', { method: 'POST' }).catch(() => {});
  const old = chatMsgs.find((x) => x.id === m.id);
  if (old) {
    old.viewed_at = new Date().toISOString();
    old.file_id = null;
    renderChat('keep');
  }
}
function onViewed(v) {
  const old = chatMsgs.find((x) => x.id === v.id);
  if (!old) return;
  old.viewed_at = new Date().toISOString();
  old.file_id = null;
  renderChat('keep');
}

// ---------- 대화 내보내기 (복호화된 텍스트 파일) ----------
$('#btn-export').onclick = () => exportChat().catch((err) => alert(err.message));
async function exportChat() {
  if (!current) return;
  if (!confirm('대화 내용을 텍스트 파일로 저장합니다. 사진과 파일 자체는 포함되지 않고 이름만 적힙니다. 계속할까요?')) return;
  if (current.type === 'group') await syncGroupKeys(current.id).catch(() => {});
  const all = [];
  let before = null;
  for (;;) {
    const raw = await api(historyPath(current, before));
    if (!raw.length) break;
    const rows = await Promise.all(raw.map((m) => decryptMsg(m)));
    all.unshift(...rows);
    before = rows[0].id;
    if (raw.length < 50) break;
  }
  const lines = all.map((m) => {
    const who = m.sender_id === me.id ? me.name : (m.sender_name || current.name);
    const when = new Date(m.created_at).toLocaleString('ko-KR');
    let body;
    if (m.deleted) body = '(삭제된 메시지)';
    else if (m.view_once) body = '(한 번만 보기 사진)';
    else if (m.kind === 'image') body = '[사진] ' + (m.file_name || '');
    else if (m.kind === 'file') body = '[파일] ' + (m.file_name || '');
    else body = m.text || '';
    return '[' + when + '] ' + who + ': ' + body + (m.edited_at ? ' (수정됨)' : '');
  });
  const blob = new Blob(['﻿' + lines.join('\n')], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = '대화내보내기-' + current.name + '-' + new Date().toISOString().slice(0, 10) + '.txt';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ---------- 그룹 초대 링크 ----------
$('#btn-glink').onclick = async () => {
  if (!current || current.type !== 'group') return;
  try {
    const r = await api('/api/groups/' + current.id + '/invite', { method: 'POST' });
    prompt('아래 링크를 복사해서 보내세요 (7일 동안 유효)', location.origin + '/#invite=' + r.token);
  } catch (err) {
    alert(err.message);
  }
};

// 링크로 들어온 경우: 로그인 후 그룹 정보를 확인하고 참여합니다
async function joinPendingInvite() {
  const token = localStorage.getItem('pendingInvite');
  if (!token) return;
  localStorage.removeItem('pendingInvite');
  try {
    const info = await api('/api/invites/' + token);
    if (!confirm('"' + info.name + '" 그룹(' + info.members + '명)에 참여할까요?')) return;
    const r = await api('/api/invites/' + token + '/join', { method: 'POST' });
    await loadList();
    const g = chats.find((c) => c.type === 'group' && c.id === r.id);
    if (g) openChat(g);
  } catch (err) {
    alert(err.message);
  }
}

// ---------- 보안 · 기기 관리 · 2단계 인증 ----------
$('#btn-security').onclick = openSecurity;
$('#security-back').onclick = () => openMain('settings');
async function openSecurity() {
  $('#security-msg').textContent = '';
  $('#tfa-setup').hidden = true;
  showView('security');
  renderTfa();
  await loadSessions().catch((err) => { $('#security-msg').textContent = err.message; });
}
function renderTfa() {
  $('#tfa-state').textContent = me.totp_enabled ? '켜짐: 로그인할 때 인증 앱의 코드가 필요합니다.' : '꺼짐';
  $('#btn-2fa').textContent = me.totp_enabled ? '2단계 인증 끄기' : '2단계 인증 켜기';
}
$('#btn-2fa').onclick = async () => {
  try {
    if (me.totp_enabled) {
      const pw = prompt('2단계 인증을 끄려면 비밀번호를 입력하세요');
      if (!pw) return;
      await api('/api/2fa/disable', { method: 'POST', body: JSON.stringify({ password: pw }) });
      me.totp_enabled = false;
      renderTfa();
      $('#security-msg').textContent = '2단계 인증을 껐습니다.';
    } else {
      const r = await api('/api/2fa/setup', { method: 'POST' });
      $('#tfa-secret').textContent = r.secret;
      $('#tfa-qr').src = r.qr;
      $('#tfa-setup').hidden = false;
    }
  } catch (err) {
    $('#security-msg').textContent = err.message;
  }
};
$('#tfa-form').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/2fa/enable', { method: 'POST', body: JSON.stringify({ code: $('#tfa-code').value.trim() }) });
    me.totp_enabled = true;
    $('#tfa-setup').hidden = true;
    $('#tfa-code').value = '';
    renderTfa();
    $('#security-msg').textContent = '2단계 인증을 켰습니다.';
  } catch (err) {
    $('#security-msg').textContent = err.message;
  }
};
async function loadSessions() {
  const list = await api('/api/sessions');
  const ul = $('#sess-list');
  ul.innerHTML = '';
  for (const s of list) {
    const li = document.createElement('li');
    li.textContent = s.device + ' · 마지막 사용 ' + listTime(s.last_seen) + (s.current ? ' (이 기기)' : '');
    if (!s.current) li.appendChild(btn('종료', async () => { await api('/api/sessions/' + s.id, { method: 'DELETE' }); await loadSessions(); }, 'link'));
    ul.appendChild(li);
  }
}
$('#btn-revoke-others').onclick = async () => {
  if (!confirm('이 기기를 제외한 모든 기기에서 로그아웃할까요?')) return;
  try {
    await api('/api/sessions/revoke-others', { method: 'POST' });
    await loadSessions();
  } catch (err) {
    $('#security-msg').textContent = err.message;
  }
};

// ---------- 이모지 반응 / 안전 번호 / 예약 전송 ----------
const REACTION_EMOJI = ['👍', '❤️', '😂', '😮', '😢', '🙏'];
function toggleReaction(m, emoji) {
  socket.emit('reaction:toggle', { id: m.id, emoji }, (res) => {
    if (res && res.error) alert(res.error);
  });
}
function onReaction(u) {
  const old = chatMsgs.find((x) => x.id === u.id);
  if (!old) return;
  old.reactions = u.reactions;
  renderChat('keep');
}

// 안전 번호: 두 사람의 공개키로 만든 숫자. 양쪽 화면에서 같아야 중간에서 바꿔치기가 없습니다
async function safetyNumber(peerPub) {
  const a = myKey.pubB64, b = peerPub;
  const [x, y] = a < b ? [a, b] : [b, a];
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(x + '|' + y)));
  const out = [];
  for (let i = 0; i < 30; i += 5) {
    let n = 0;
    for (let k = 0; k < 5; k++) n = n * 256 + d[i + k];
    out.push(String(n % 100000).padStart(5, '0'));
  }
  return out.join(' ');
}
$('#btn-safety').onclick = async () => {
  if (!current || current.type !== 'dm') return;
  try {
    const r = await api('/api/users/' + current.id + '/pubkey');
    if (!r.pubkey || !myKey) return alert('아직 암호화 키가 준비되지 않았습니다');
    alert('안전 번호\n\n' + (await safetyNumber(r.pubkey)) + '\n\n상대방 기기에서도 같은 번호가 보이면 대화가 안전합니다.');
  } catch (err) {
    alert(err.message);
  }
};

// ---------- 예약 전송 (대화상자 · 목록 · 취소) ----------
let PREMIUM_ON = false;
const schedMaxMs = () => (PREMIUM_ON ? 90 : 30) * 24 * 3600 * 1000;
let schedFile = null; // { fileId, meta } - 예약에 붙일 암호화된 파일
function toLocalInput(d) {
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
}
// 시간을 입력하는 즉시 확인: 전송까지 남은 시간을 보여 주고, 조건이 맞지 않으면 예약 버튼을 막습니다
function sdCheck() {
  const v = $('#sd-time').value;
  const at = v ? new Date(v) : null;
  let msg = '보낼 시간을 선택하세요';
  let ok = false;
  if (at && !isNaN(at)) {
    const diff = at - Date.now();
    if (diff < 60 * 1000) msg = '지금부터 1분 이후 시간을 선택하세요';
    else if (diff > schedMaxMs()) msg = (PREMIUM_ON ? '90' : '30') + '일 이내 시간만 예약할 수 있습니다';
    else {
      const mins = Math.round(diff / 60000);
      const left = mins >= 60 ? Math.floor(mins / 60) + '시간 ' + (mins % 60) + '분' : mins + '분';
      msg = at.toLocaleString('ko-KR') + ' 전송 (' + left + ' 후)';
      ok = true;
    }
  }
  if (!$('#sd-text').value.trim() && !schedFile) {
    ok = false;
    msg = '내용이나 파일을 입력하세요';
  }
  $('#sd-check').textContent = msg;
  $('#sd-ok').disabled = !ok;
}
$('#btn-schedule').onclick = () => {
  if (!current || current.type !== 'dm') return alert('1:1 대화에서만 예약 전송할 수 있습니다');
  schedFile = null;
  $('#sd-text').value = $('#msg-input').value.trim();
  $('#sd-file').textContent = '';
  $('#sd-time').min = toLocalInput(new Date(Date.now() + 60 * 1000));
  $('#sd-time').max = toLocalInput(new Date(Date.now() + schedMaxMs()));
  $('#sd-time').value = '';
  $('#sched-dialog').hidden = false;
  sdCheck();
};
$('#sd-text').oninput = sdCheck;
$('#sd-time').oninput = sdCheck;
$('#sd-time').onchange = sdCheck;
$('#sd-cancel').onclick = () => { $('#sched-dialog').hidden = true; };
$('#sd-attach').onclick = () => $('#sd-file-input').click();
$('#sd-file-input').onchange = async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  if (file.size > 20 * 1024 * 1024) return alert('20MB 이하 파일만 보낼 수 있습니다');
  try {
    const k = await peerKey(current.id);
    const sealed = await E2EE.sealBytes(k, new Uint8Array(await file.arrayBuffer()));
    const r = await fetch('/api/files', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/octet-stream', 'X-File-Name': encodeURIComponent('encrypted') },
      body: sealed.data,
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || '파일 업로드에 실패했습니다');
    schedFile = { fileId: j.id, meta: { name: file.name, mime: file.type || 'application/octet-stream', iv: sealed.iv } };
    $('#sd-file').textContent = '📎 ' + file.name;
    sdCheck();
  } catch (err) {
    alert(err.message);
  }
};
$('#sd-ok').onclick = async () => {
  const at = new Date($('#sd-time').value);
  try {
    const k = await peerKey(current.id);
    const body = await E2EE.seal(k, { t: $('#sd-text').value.trim(), f: schedFile ? schedFile.meta : null });
    await api('/api/scheduled', {
      method: 'POST',
      body: JSON.stringify({ to: current.id, text: body, fileId: schedFile ? schedFile.fileId : null, sendAt: at.toISOString() }),
    });
    schedFile = null;
    $('#sched-dialog').hidden = true;
    $('#msg-input').value = '';
    alert('예약되었습니다: ' + at.toLocaleString('ko-KR'));
  } catch (err) {
    alert(err.message);
  }
};

// 예약 목록 / 취소
$('#btn-sched-list').onclick = () => openScheduled().catch((err) => alert(err.message));
$('#sched-back').onclick = () => openMain('settings');
async function openScheduled() {
  showView('scheduled');
  await loadScheduled();
}
async function loadScheduled() {
  const list = await api('/api/scheduled');
  const ul = $('#sched-list');
  ul.innerHTML = '';
  if (!list.length) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = '예약된 메시지가 없습니다';
    ul.appendChild(li);
    return;
  }
  for (const s of list) {
    const li = document.createElement('li');
    const main = document.createElement('div');
    main.className = 'row-main';
    main.innerHTML = '<div class="row-name"></div><div class="row-sub"></div>';
    main.querySelector('.row-name').textContent = s.recipient_name + (s.file_id ? ' · 파일 포함' : '');
    main.querySelector('.row-sub').textContent = new Date(s.send_at).toLocaleString('ko-KR') + ' 전송';
    li.appendChild(main);
    li.appendChild(btn('취소', async () => {
      if (!confirm('이 예약을 취소할까요?')) return;
      await api('/api/scheduled/' + s.id, { method: 'DELETE' });
      await loadScheduled();
    }, 'link'));
    ul.appendChild(li);
  }
}

// ---------- 시작 / 소켓 ----------
async function start() {
  try {
    me = await api('/api/me');
  } catch (err) {
    if (err.message.includes('제한')) alert(err.message);
    return logout();
  }
  const pw = pendingPassword;
  pendingPassword = null;
  try {
    const st = await setupKeys(pw);
    if (st === 'locked') {
      $('#ul-pass').value = '';
      $('#unlock-msg').textContent = '';
      showView('unlock');
      return;
    }
  } catch (err) {
    alert(err.message);
  }
  await enterMain();
}

async function enterMain() {
  openMain('friends');
  renderMe();
  $('#btn-admin').hidden = !me.is_admin;
  refreshPlanState().catch(() => {});
  handleBillingReturn();
  loadMutes().catch(() => {});
  renderReceiptsBtn();
  renderVisBtns();
  await loadRequests();
  await loadList();
  connectSocket();
  enablePush(true).catch(() => {}); // 이미 허용된 경우에만 조용히 구독
  joinPendingInvite();
}

function connectSocket() {
  if (socket) socket.disconnect();
  socket = io({ auth: { token } });
  socket.on('message:new', onMessage);
  socket.on('read:dm', onRead);
  socket.on('device:request', (r) => approveDevice(r).catch((err) => alert(err.message)));
  socket.on('message:updated', onUpdated);
  socket.on('message:deleted', onDeleted);
  socket.on('message:viewed', onViewed);
  socket.on('reaction:updated', onReaction);
  socket.on('call:signal', onCallSignal);
  socket.on('call:peer-joined', ({ groupId, sid, name }) => {
    if (callState && callState.groupId === groupId) callState.names.set(sid, name);
  });
  socket.on('call:peer-left', ({ groupId, sid }) => {
    if (callState && callState.groupId === groupId) removeCallPeer(sid);
  });
  socket.on('group:board', ({ groupId }) => {
    if (current && current.type === 'group' && current.id === groupId) refreshBoard(groupId).catch(() => {});
  });
  socket.on('call:state', ({ groupId, count }) => {
    callCounts.set(groupId, count);
    renderCallBanner();
  });
  socket.on('connect_error', (err) => {
    if (err.message === 'unauthorized') logout();
  });
}

// 친구 목록과 대화 목록(마지막 메시지, 안 읽은 수)을 함께 불러옵니다
async function loadList() {
  [friends, chats] = await Promise.all([api('/api/friends'), api('/api/chats')]);
  for (const c of chats) if (c.last && c.last.enc) c.last = await decryptMsg({ ...c.last, group_id: c.type === 'group' ? c.id : null }, c.id);
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
    li.appendChild(avatarNodeFor(f.id, f.name));
    const main = document.createElement('div');
    main.className = 'row-main';
    main.innerHTML = '<div class="row-name"></div><div class="row-sub"></div>';
    main.querySelector('.row-name').textContent = f.name;
    const prefix = f.online ? '온라인 · ' : (f.last_seen ? listTime(f.last_seen) + ' 접속 · ' : '');
    main.querySelector('.row-sub').textContent = prefix + (f.status_msg || '@' + f.username);
    li.appendChild(main);
    const pbtn = document.createElement('button');
    pbtn.type = 'button';
    pbtn.className = 'ghost small-btn';
    pbtn.textContent = '프로필';
    pbtn.onclick = (e) => {
      e.stopPropagation();
      openFriendProfilePick(f);
    };
    li.appendChild(pbtn);
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
  li.appendChild(avatarNodeFor(c.type === 'dm' ? c.id : null, c.name));

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
  clearCompose();
  current = t;
  oldestId = null;
  chatMsgs = [];
  setChatOpen(true);
  $('#chat-title').textContent = t.name;
  $('#dm-actions').hidden = t.type !== 'dm';
  if (t.type === 'dm') refreshReceiptBtn();
  $('#group-actions').hidden = t.type !== 'group';
  $('#call-banner').hidden = true;
  $('#notice-banner').hidden = true;
  renderMuteBtn();
  if (t.type === 'group') refreshBoard(t.id).catch(() => {});
  if (t.type === 'group') socket.emit('call:status', { groupId: t.id }, (r) => {
    if (r && !r.error) {
      callCounts.set(t.id, r.count);
      renderCallBanner();
    }
  });
  $('#compose').hidden = false;
  $('#chat-box').innerHTML = '';
  if (t.type === 'group') await syncGroupKeys(t.id).catch(() => {});
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
  const rows = await Promise.all((await api(historyPath(current, oldestId))).map((m) => decryptMsg(m)));
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
    if (!cont) slot.appendChild(avatarNodeFor(m.sender_id, m.sender_name || (current ? current.name : '?'), 'sm'));
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
  bubble.onclick = () => openMsgMenu(m);
  if (m.view_once && !m.viewed_at && m.file_id) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ghost';
    b.textContent = mine ? '한 번만 보기 (상대가 열면 사라짐)' : '한 번만 보기 · 눌러서 열기';
    b.onclick = (e) => { e.stopPropagation(); if (!mine) openViewOnce(m); };
    bubble.appendChild(b);
  } else if (m.view_once) {
    const d = document.createElement('div');
    d.className = 'muted';
    d.textContent = '열람한 사진';
    bubble.appendChild(d);
  } else if (m.kind === 'image' && m.file_id) {
    const img = document.createElement('img');
    img.className = 'thumb';
    img.alt = '사진';
    fileUrl(m).then((url) => { img.src = url; }).catch(() => { img.alt = '[이미지를 불러올 수 없음]'; });
    bubble.appendChild(img);
  } else if (m.kind === 'file' && m.file_id) {
    const a = document.createElement('a');
    a.href = '#';
    a.textContent = '📎 ' + (m.file_name || '첨부 파일') + ' 받기';
    a.onclick = async (e) => {
      e.preventDefault();
      try {
        const url = await fileUrl(m);
        const d = document.createElement('a');
        d.href = url;
        d.download = m.file_name || 'file';
        d.click();
      } catch (err) { alert(err.message); }
    };
    bubble.appendChild(a);
  }
  if (m.deleted) {
    const t = document.createElement('div');
    t.className = 'muted';
    t.textContent = '삭제된 메시지입니다';
    bubble.appendChild(t);
  } else {
    if (m.reply_to) bubble.prepend(quoteEl(m));
    if (m.text) {
      const t = document.createElement('div');
      t.textContent = m.text;
      bubble.appendChild(t);
    }
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
  tm.textContent = (m.edited_at ? '수정됨 · ' : '') + timeLabel(m.created_at);
  meta.appendChild(tm);

  if (mine) line.append(meta, bubble);
  else line.append(bubble, meta);
  col.appendChild(line);
  if (m.reactions && m.reactions.length && !m.deleted) {
    const rx = document.createElement('div');
    rx.className = 'reactions';
    const counts = {};
    for (const r of m.reactions) {
      counts[r.emoji] = counts[r.emoji] || { n: 0, mine: false };
      counts[r.emoji].n++;
      if (r.user === me.id) counts[r.emoji].mine = true;
    }
    for (const e of Object.keys(counts)) {
      const c = document.createElement('span');
      c.className = 'rx' + (counts[e].mine ? ' mine' : '');
      c.textContent = e + ' ' + counts[e].n;
      c.onclick = () => toggleReaction(m, e);
      rx.appendChild(c);
    }
    col.appendChild(rx);
  }
  row.appendChild(col);
  return row;
}

function emitSend(payload) {
  socket.emit('message:send', payload, (res) => {
    if (res && res.error) alert(res.error);
  });
}

// 1:1은 상대 키로 암호화해서 보내고, 그룹은 기존처럼 보냅니다
async function sendPayload(extra) {
  if (isBotChat(current) && !extra.fileId) return emitSend({ to: current.id, text: extra.text || '', fileId: null, replyTo: null });
  try {
    const sk = extra.sk || await sendKey();
    if (!sk) return emitSend({ groupId: current.id, text: extra.text || '', fileId: extra.fileId || null, replyTo: extra.replyTo || null });
    const body = await E2EE.seal(sk.key, { t: extra.text || '', f: extra.fileMeta || null });
    const payload = { text: body, fileId: extra.fileId || null, enc: true, replyTo: extra.replyTo || null, viewOnce: !!extra.viewOnce };
    if (current.type === 'group') Object.assign(payload, { groupId: current.id, epoch: sk.epoch });
    else payload.to = current.id;
    emitSend(payload);
  } catch (err) {
    alert(err.message);
  }
}

$('#compose').onsubmit = (e) => {
  e.preventDefault();
  const text = $('#msg-input').value.trim();
  if (!text || !current) return;
  if (editing) submitEdit(editing, text);
  else sendPayload({ text, replyTo: replyTo ? replyTo.id : null });
  $('#msg-input').value = '';
  clearCompose();
};

// 파일 보내기 (2MB 이하, 이미지 / PDF / 텍스트). 1:1은 파일도 암호화해서 올립니다.
$('#attach').onchange = async (e) => {
  if (isBotChat(current)) { alert('봇에게는 파일을 보낼 수 없습니다'); e.target.value = ''; return; }
  const file = e.target.files[0];
  e.target.value = '';
  if (!file || !current) return;
  if (file.size > 20 * 1024 * 1024) return alert('20MB 이하 파일만 보낼 수 있습니다');
  try {
    let body = file, ctype = file.type || 'application/octet-stream', fname = file.name, fileMeta = null;
    const viewOnce = current.type === 'dm' && (file.type || '').startsWith('image/') && confirm('한 번만 볼 수 있는 사진으로 보낼까요? 상대가 열면 사라집니다.');
    const sk = await sendKey();
    if (sk) {
      const sealed = await E2EE.sealBytes(sk.key, new Uint8Array(await file.arrayBuffer()));
      body = sealed.data;
      ctype = 'application/octet-stream';
      fname = 'encrypted';
      fileMeta = { name: file.name, mime: file.type || 'application/octet-stream', iv: sealed.iv };
    }
    const r = await fetch('/api/files', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': ctype,
        'X-File-Name': encodeURIComponent(fname),
      },
      body,
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || '파일 업로드에 실패했습니다');
    const text = $('#msg-input').value.trim();
    await sendPayload({ fileId: j.id, text, fileMeta, sk, replyTo: replyTo ? replyTo.id : null, viewOnce });
    clearCompose();
    $('#msg-input').value = '';
  } catch (err) {
    alert(err.message);
  }
};

// 새 메시지 수신: 열린 대화면 말풍선 추가, 아니면 대화 목록과 뱃지 갱신
async function onMessage(raw) {
  const m = await decryptMsg(raw);
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

// 대화별 읽음 표시 on/off (상대 화면에서 내 읽음 표시가 보이는지)
async function refreshReceiptBtn() {
  const r = await api('/api/prefs/dm/' + current.id).catch(() => null);
  $('#btn-receipt').dataset.on = r ? String(r.receipts) : '';
  if (r) $('#btn-receipt').textContent = r.receipts ? '읽음 끄기' : '읽음 켜기';
}
$('#btn-receipt').onclick = async () => {
  if (!current || current.type !== 'dm') return;
  const on = $('#btn-receipt').dataset.on === 'true';
  try {
    await api('/api/prefs/dm/' + current.id, { method: 'POST', body: JSON.stringify({ receipts: !on }) });
    await refreshReceiptBtn();
  } catch (err) {
    alert(err.message);
  }
};

// 전체 읽음 표시 on/off (설정 탭)
function renderReceiptsBtn() {
  $('#btn-receipts').textContent = '읽음 표시 보내기: ' + (me.receipts_on ? '켜짐' : '꺼짐');
}
// 프로필 공개 설정 (상태 메시지, 온라인 표시, 마지막 접속)
const VIS = [
  ['btn-vis-photo', 'show_photo', 'showPhoto', '프로필 사진 공개'],
  ['btn-vis-status', 'show_status_msg', 'showStatus', '상태 메시지 공개'],
  ['btn-vis-online', 'show_online', 'showOnline', '온라인 표시'],
  ['btn-vis-seen', 'show_last_seen', 'showLastSeen', '마지막 접속 공개'],
];
function renderVisBtns() {
  for (const v of VIS) $('#' + v[0]).textContent = v[3] + ': ' + (me[v[1]] ? '켜짐' : '꺼짐');
}
for (const v of VIS) {
  $('#' + v[0]).onclick = async () => {
    const next = !me[v[1]];
    try {
      await api('/api/prefs/profile', { method: 'POST', body: JSON.stringify({ [v[2]]: next }) });
      me[v[1]] = next;
      renderVisBtns();
    } catch (err) {
      alert(err.message);
    }
  };
}

// 프로필 사진 바꾸기: 가로·세로 256px 이하 JPEG로 줄여서 올립니다
async function resizeImage(file) {
  const bmp = await createImageBitmap(file);
  const s = Math.min(1, 256 / Math.max(bmp.width, bmp.height));
  const c = document.createElement('canvas');
  c.width = Math.round(bmp.width * s);
  c.height = Math.round(bmp.height * s);
  c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
  return new Promise((res) => c.toBlob(res, 'image/jpeg', 0.9));
}
$('#btn-avatar').onclick = () => $('#avatar-input').click();
$('#avatar-input').onchange = async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    const blob = await resizeImage(file);
    const r = await fetch('/api/files', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'image/jpeg', 'X-File-Name': encodeURIComponent('profile.jpg') },
      body: blob,
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || '사진 업로드에 실패했습니다');
    await api('/api/me/avatar', { method: 'POST', body: JSON.stringify({ fileId: j.id }) });
    avatarCache.delete(me.id);
    me.has_photo = true;
    renderMe();
    await loadList();
    alert('프로필 사진을 바꿨습니다.');
  } catch (err) {
    alert(err.message);
  }
};

$('#btn-receipts').onclick = async () => {
  const next = !me.receipts_on;
  try {
    await api('/api/prefs/receipts', { method: 'POST', body: JSON.stringify({ receiptsOn: next }) });
    me.receipts_on = next;
    renderReceiptsBtn();
  } catch (err) {
    alert(err.message);
  }
};

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
    await syncGroupKeys(current.id).catch(() => {});
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

// ===== 그룹 통화 (메쉬 WebRTC, 무료 STUN 사용) =====
const RTC_CFG = { iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }] };
const callCounts = new Map(); // groupId -> 현재 참여자 수
let callState = null; // { groupId, stream, peers: Map(sid -> { pc, pending }), names: Map(sid -> 이름) }

function renderCallBanner() {
  const gid = current && current.type === 'group' ? current.id : null;
  const n = gid ? callCounts.get(gid) || 0 : 0;
  const inThis = !!callState && callState.groupId === gid;
  $('#call-banner-text').textContent = `통화 중 · ${n}명 참여`;
  $('#call-banner').hidden = !(n > 0 && !inThis);
}

function getCallMedia() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    return Promise.reject(new Error('이 브라우저는 통화를 지원하지 않습니다'));
  }
  return navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 640, height: 480 } }).catch(() =>
    navigator.mediaDevices.getUserMedia({ audio: true }).catch(() => {
      throw new Error('마이크 권한이 필요합니다');
    })
  );
}

async function joinCall(gid) {
  if (callState) {
    if (callState.groupId === gid) return;
    return alert('다른 통화에 참여 중입니다');
  }
  let stream;
  try {
    stream = await getCallMedia();
  } catch (e) {
    return alert(e.message);
  }
  callState = { groupId: gid, stream, peers: new Map(), names: new Map() };
  $('#call-view').hidden = false;
  addCallTile('me', stream, '나', true);
  renderCallBanner();
  socket.emit('call:join', { groupId: gid }, async (res) => {
    if (!callState || callState.groupId !== gid) return;
    if (!res || res.error) {
      alert((res && res.error) || '통화에 참여하지 못했습니다');
      return leaveCall();
    }
    // 기존 참여자 각각에게 offer를 보냄 (새로 들어온 사람이 연결을 시작)
    for (const p of res.peers) {
      if (!callState || callState.groupId !== gid) return;
      callState.names.set(p.sid, p.name);
      await offerTo(p.sid, makePeer(p.sid));
    }
  });
}

function sendSignal(sid, data) {
  if (callState) socket.emit('call:signal', { groupId: callState.groupId, to: sid, data });
}

function makePeer(sid) {
  if (callState.peers.has(sid)) return callState.peers.get(sid);
  const pc = new RTCPeerConnection(RTC_CFG);
  const entry = { pc, pending: [] };
  callState.peers.set(sid, entry);
  callState.stream.getTracks().forEach((t) => pc.addTrack(t, callState.stream));
  pc.onicecandidate = (e) => {
    if (e.candidate) sendSignal(sid, { candidate: e.candidate });
  };
  pc.ontrack = (e) => addCallTile(sid, e.streams[0], callState.names.get(sid) || '참여자', false);
  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') removeCallPeer(sid);
  };
  return entry;
}

async function offerTo(sid, entry) {
  const offer = await entry.pc.createOffer();
  await entry.pc.setLocalDescription(offer);
  sendSignal(sid, { sdp: entry.pc.localDescription });
}

async function onCallSignal({ groupId, from, data }) {
  if (!callState || callState.groupId !== groupId || !data) return;
  try {
    let entry = callState.peers.get(from);
    if (data.sdp) {
      if (!entry) {
        if (data.sdp.type !== 'offer') return;
        entry = makePeer(from);
      }
      await entry.pc.setRemoteDescription(data.sdp);
      for (const c of entry.pending.splice(0)) await entry.pc.addIceCandidate(c).catch(() => {});
      if (data.sdp.type === 'offer') {
        await entry.pc.setLocalDescription(await entry.pc.createAnswer());
        sendSignal(from, { sdp: entry.pc.localDescription });
      }
    } else if (data.candidate) {
      if (!entry) return;
      if (entry.pc.remoteDescription) await entry.pc.addIceCandidate(data.candidate).catch(() => {});
      else entry.pending.push(data.candidate);
    }
  } catch (e) {
    console.warn('call signal failed', e);
  }
}

function addCallTile(id, stream, name, mine) {
  const grid = $('#call-grid');
  let tile = grid.querySelector(`[data-sid="${id}"]`);
  if (!tile) {
    tile = document.createElement('div');
    tile.className = 'call-tile';
    tile.dataset.sid = id;
    const v = document.createElement('video');
    v.autoplay = true;
    v.playsInline = true;
    if (mine) v.muted = true;
    const label = document.createElement('span');
    label.className = 'call-tile-name';
    tile.append(v, label);
    grid.append(tile);
  }
  const v = tile.querySelector('video');
  if (v.srcObject !== stream) v.srcObject = stream;
  tile.querySelector('.call-tile-name').textContent = name;
}

function removeCallPeer(sid) {
  if (!callState) return;
  const entry = callState.peers.get(sid);
  if (entry) {
    entry.pc.close();
    callState.peers.delete(sid);
  }
  callState.names.delete(sid);
  const tile = $('#call-grid').querySelector(`[data-sid="${sid}"]`);
  if (tile) tile.remove();
}

function leaveCall() {
  if (!callState) return;
  const gid = callState.groupId;
  for (const sid of [...callState.peers.keys()]) removeCallPeer(sid);
  callState.stream.getTracks().forEach((t) => t.stop());
  $('#call-grid').innerHTML = '';
  if (socket) socket.emit('call:leave', { groupId: gid });
  callState = null;
  $('#call-mic').textContent = '마이크 끄기';
  $('#call-cam').textContent = '카메라 끄기';
  $('#call-view').hidden = true;
  renderCallBanner();
}

$('#btn-call').onclick = () => {
  if (current && current.type === 'group') joinCall(current.id);
};
$('#call-join').onclick = () => {
  if (current && current.type === 'group') joinCall(current.id);
};
$('#call-end').onclick = () => leaveCall();
$('#call-mic').onclick = () => {
  const t = callState && callState.stream.getAudioTracks()[0];
  if (!t) return;
  t.enabled = !t.enabled;
  $('#call-mic').textContent = t.enabled ? '마이크 끄기' : '마이크 켜기';
};
$('#call-cam').onclick = () => {
  const t = callState && callState.stream.getVideoTracks()[0];
  if (!t) return;
  t.enabled = !t.enabled;
  $('#call-cam').textContent = t.enabled ? '카메라 끄기' : '카메라 켜기';
};

// ===== 상태 대시보드 (관리자) =====
function fmtBytes(n) {
  let v = Number(n) || 0;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return v.toFixed(i ? 1 : 0) + ' ' + units[i];
}
function fmtUptime(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return (d ? d + '일 ' : '') + h + '시간 ' + m + '분';
}
async function loadStats() {
  const box = $('#admin-stats');
  if (!box || $('#view-admin').hidden) return;
  const s = await api('/api/admin/stats');
  const cards = [
    ['지금 접속', s.online_sockets + '개 연결'],
    ['진행 중 통화', s.call_rooms + '방 · ' + s.call_participants + '명'],
    ['전체 사용자', s.users.total + '명 (인증 ' + s.users.verified + ' · 정지 ' + s.users.banned + ')'],
    ['신규 가입', '오늘 ' + s.users.new_1d + ' · 7일 ' + s.users.new_7d],
    ['활성 사용자', '24시간 ' + s.users.active_1d + ' · 7일 ' + s.users.active_7d],
    ['메시지', '전체 ' + s.messages.total + ' · 오늘 ' + s.messages.last_1d + ' · 7일 ' + s.messages.last_7d],
    ['그룹 메시지', s.messages.group_msgs + '건'],
    ['그룹 · 예약 메시지', s.misc.groups + '개 · ' + s.misc.scheduled + '건'],
    ['파일', s.misc.files + '개 · ' + fmtBytes(s.misc.file_bytes)],
    ['DB 사용량', fmtBytes(s.db_bytes)],
    ['신고 건수', s.misc.reports + '건'],
    ['활성 세션', s.misc.sessions + '개'],
    ['서버 가동', fmtUptime(s.uptime_s) + ' · 메모리 ' + fmtBytes(s.rss)],
  ];
  box.innerHTML = '';
  for (const [k, v] of cards) {
    const d = document.createElement('div');
    d.className = 'stat';
    const label = document.createElement('span');
    label.className = 'stat-k';
    label.textContent = k;
    const val = document.createElement('b');
    val.textContent = v;
    d.append(label, val);
    box.append(d);
  }
}
$('#stats-refresh').onclick = () => loadStats().catch((e) => alert(e.message));
setInterval(() => loadStats().catch(() => {}), 15000);

// ===== 멀티 프로필 =====
let editingProfileId = null;

function resetProfileForm() {
  editingProfileId = null;
  $('#pf-name').value = '';
  $('#pf-status').value = '';
  $('#pf-photo').value = '';
  $('#pf-form-title').textContent = '새 프로필';
}

async function openProfiles() {
  $('#pf-msg').textContent = '';
  resetProfileForm();
  showView('profiles');
  await renderProfileList().catch((e) => { $('#pf-msg').textContent = e.message; });
}
$('#btn-profiles').onclick = () => openProfiles();
$('#pf-back').onclick = () => openMain('settings');
$('#pf-reset').onclick = () => {
  resetProfileForm();
  $('#pf-msg').textContent = '';
};

async function renderProfileList() {
  const list = await api('/api/profiles');
  const ul = $('#pf-list');
  ul.innerHTML = '';
  const base = document.createElement('li');
  base.className = 'pf-item';
  base.innerHTML = '<div class="row-main"><div class="row-name"></div><div class="row-sub">기본 프로필 · 설정의 프로필 편집에서 바꿉니다</div></div>';
  base.querySelector('.row-name').textContent = me.name;
  ul.appendChild(base);
  for (const p of list) {
    const li = document.createElement('li');
    li.className = 'pf-item';
    const main = document.createElement('div');
    main.className = 'row-main';
    main.innerHTML = '<div class="row-name"></div><div class="row-sub"></div>';
    main.querySelector('.row-name').textContent = p.name;
    main.querySelector('.row-sub').textContent = (p.status_msg || '상태 메시지 없음') + (p.has_photo ? ' · 사진 있음' : '');
    main.onclick = () => {
      editingProfileId = p.id;
      $('#pf-name').value = p.name;
      $('#pf-status').value = p.status_msg || '';
      $('#pf-photo').value = '';
      $('#pf-form-title').textContent = '프로필 수정';
      $('#pf-msg').textContent = '';
    };
    li.appendChild(main);
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'ghost small-btn';
    del.textContent = '삭제';
    del.onclick = async () => {
      if (!confirm('이 프로필을 삭제할까요? 이 프로필을 쓰던 친구는 기본 프로필이 보입니다.')) return;
      try {
        await api('/api/profiles/' + p.id, { method: 'DELETE' });
        if (editingProfileId === p.id) resetProfileForm();
        await renderProfileList();
        await loadList();
      } catch (e) {
        $('#pf-msg').textContent = e.message;
      }
    };
    li.appendChild(del);
    ul.appendChild(li);
  }
}

async function uploadProfilePhoto(pid, file) {
  const blob = await resizeImage(file);
  const r = await fetch('/api/files', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'image/jpeg', 'X-File-Name': encodeURIComponent('profile.jpg') },
    body: blob,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || '사진 업로드에 실패했습니다');
  await api('/api/profiles/' + pid + '/avatar', { method: 'POST', body: JSON.stringify({ fileId: j.id }) });
}

$('#pf-form').onsubmit = async (e) => {
  e.preventDefault();
  const name = $('#pf-name').value.trim();
  const statusMsg = $('#pf-status').value.trim();
  const photo = $('#pf-photo').files[0];
  try {
    let id = editingProfileId;
    if (id) {
      await api('/api/profiles/' + id, { method: 'PATCH', body: JSON.stringify({ name, statusMsg }) });
    } else {
      const r = await api('/api/profiles', { method: 'POST', body: JSON.stringify({ name, statusMsg }) });
      id = r.id;
    }
    if (photo) await uploadProfilePhoto(id, photo);
    resetProfileForm();
    $('#pf-msg').textContent = '저장했습니다.';
    await renderProfileList();
    await loadList();
  } catch (err) {
    $('#pf-msg').textContent = err.message;
  }
};

// 친구별 프로필 선택 (친구 목록의 '프로필' 버튼)
async function openFriendProfilePick(f) {
  try {
    const [profiles, assigns] = await Promise.all([api('/api/profiles'), api('/api/profiles/assign')]);
    const a = assigns.find((x) => x.viewer_id === f.id);
    const curId = a ? a.profile_id : null;
    const items = [[(curId == null ? '✓ ' : '') + '기본 프로필', () => setFriendProfile(f, null)]];
    for (const p of profiles) items.push([(curId === p.id ? '✓ ' : '') + p.name, () => setFriendProfile(f, p.id)]);
    if (!profiles.length) items.push(['프로필 만들기 (설정 › 프로필 관리)', () => openProfiles()]);
    openSheet(items);
  } catch (e) {
    alert(e.message);
  }
}

async function setFriendProfile(f, profileId) {
  try {
    await api('/api/profiles/assign/' + f.id, { method: 'PUT', body: JSON.stringify({ profileId }) });
    avatarCache.delete(f.id);
    await loadList();
  } catch (e) {
    alert(e.message);
  }
}

// ===== AI 어시스턴트 =====
function renderAi(list) {
  const box = $('#ai-box');
  box.innerHTML = '';
  if (!list.length) {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = '무엇이든 물어보세요.';
    box.append(p);
  }
  for (const m of list) {
    const d = document.createElement('div');
    d.className = 'ai-bubble ' + (m.role === 'user' ? 'me' : 'ai');
    d.textContent = m.content;
    box.append(d);
  }
  box.scrollTop = box.scrollHeight;
}

async function openAi() {
  $('#ai-msg').textContent = '';
  showView('ai');
  try {
    renderAi(await api('/api/ai/messages'));
  } catch (e) {
    $('#ai-msg').textContent = e.message;
  }
}
$('#btn-ai').onclick = () => openAi();
$('#ai-back').onclick = () => openMain('settings');

$('#ai-form').onsubmit = async (e) => {
  e.preventDefault();
  const input = $('#ai-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  $('#ai-msg').textContent = 'AI가 답하는 중...';
  try {
    await api('/api/ai/messages', { method: 'POST', body: JSON.stringify({ text }) });
    $('#ai-msg').textContent = '';
  } catch (err) {
    $('#ai-msg').textContent = err.message;
  }
  // 실패해도 사용자 메시지는 저장되므로 목록을 다시 불러와 맞춤
  try {
    renderAi(await api('/api/ai/messages'));
  } catch (_) {}
};

$('#ai-clear').onclick = async () => {
  if (!confirm('AI 대화 내용을 모두 지울까요?')) return;
  try {
    await api('/api/ai/messages', { method: 'DELETE' });
    renderAi([]);
    $('#ai-msg').textContent = '';
  } catch (e) {
    $('#ai-msg').textContent = e.message;
  }
};

// ===== 봇 =====
function isBotChat(c) {
  if (!c || c.type !== 'dm') return false;
  const f = friends.find((x) => x.id === c.id);
  return !!(f && f.is_bot);
}

async function openBots() {
  showView('bots');
  try {
    const list = await api('/api/bots');
    const ul = $('#bot-list');
    ul.innerHTML = '';
    for (const b of list) {
      const li = document.createElement('li');
      const main = document.createElement('div');
      main.className = 'row-main';
      main.innerHTML = '<div class="row-name"></div><div class="row-sub"></div>';
      main.querySelector('.row-name').textContent = b.name;
      main.querySelector('.row-sub').textContent = b.desc;
      li.appendChild(main);
      const act = document.createElement('button');
      act.type = 'button';
      act.className = 'ghost small-btn';
      act.textContent = b.added ? '삭제' : '추가';
      act.onclick = async () => {
        try {
          await api('/api/bots/' + b.id + '/add', { method: b.added ? 'DELETE' : 'POST' });
          await loadList();
          await openBots();
        } catch (e) {
          alert(e.message);
        }
      };
      li.appendChild(act);
      ul.appendChild(li);
    }
  } catch (e) {
    alert(e.message);
  }
}
$('#btn-bots').onclick = () => openBots();
$('#bots-back').onclick = () => openMain('settings');

// ===== 프리미엄 구독 (토스페이먼츠) =====
let tossSdkPromise = null;
function loadTossSdk() {
  if (window.TossPayments) return Promise.resolve();
  if (!tossSdkPromise) {
    tossSdkPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://js.tosspayments.com/v1/payment';
      s.onload = () => resolve();
      s.onerror = () => {
        tossSdkPromise = null;
        reject(new Error('결제 모듈을 불러오지 못했습니다'));
      };
      document.head.appendChild(s);
    });
  }
  return tossSdkPromise;
}

async function refreshPlanState() {
  const s = await api('/api/billing/status');
  PREMIUM_ON = !!s.premium;
  return s;
}

function fmtDay(v) {
  return new Date(v).toLocaleDateString('ko-KR');
}

async function openPlan() {
  $('#plan-msg').textContent = '';
  showView('plan');
  try {
    const s = await refreshPlanState();
    if (s.premium) {
      $('#plan-state').textContent = '프리미엄 이용 중 · ' + fmtDay(s.period_end) + '까지' +
        (s.status === 'canceled' ? ' (해지됨, 자동 결제 없음)' : ' (매월 자동 결제)');
    } else if (s.status === 'past_due') {
      $('#plan-state').textContent = '결제 실패로 구독이 중단되었습니다. 다시 구독해 주세요.';
    } else {
      $('#plan-state').textContent = '무료 플랜 이용 중';
    }
    $('#plan-price').textContent = '월 ' + Number(s.price).toLocaleString('ko-KR') + '원';
    $('#plan-subscribe').hidden = !!s.premium;
    $('#plan-cancel').hidden = !(s.premium && s.status === 'active');
    const ul = $('#plan-payments');
    ul.innerHTML = '';
    if (!s.payments.length) {
      const li = document.createElement('li');
      li.textContent = '결제 내역이 없습니다';
      ul.appendChild(li);
    }
    for (const p of s.payments) {
      const li = document.createElement('li');
      li.textContent = fmtDay(p.created_at) + ' · ' + Number(p.amount).toLocaleString('ko-KR') + '원 · ' +
        (p.status === 'done' ? '결제 완료' : p.status);
      ul.appendChild(li);
    }
  } catch (e) {
    $('#plan-msg').textContent = e.message;
  }
}

async function subscribePlan() {
  $('#plan-msg').textContent = '';
  try {
    const c = await api('/api/billing/config');
    if (!c.clientKey) throw new Error('결제가 아직 준비되지 않았습니다. 잠시 후 다시 시도해 주세요');
    await loadTossSdk();
    const tp = window.TossPayments(c.clientKey);
    // 결제창으로 이동 후 successUrl / failUrl 로 돌아옴
    await tp.requestBillingAuth('카드', {
      customerKey: c.customerKey,
      successUrl: location.origin + '/?billing=success',
      failUrl: location.origin + '/?billing=fail',
      customerName: me.name,
    });
  } catch (e) {
    $('#plan-msg').textContent = e.message;
  }
}

async function cancelPlan() {
  if (!confirm('구독을 해지할까요? 남은 기간까지는 계속 이용할 수 있고, 다음 자동 결제는 진행되지 않습니다.')) return;
  try {
    await api('/api/billing/cancel', { method: 'POST' });
    await openPlan();
  } catch (e) {
    $('#plan-msg').textContent = e.message;
  }
}

$('#btn-plan').onclick = () => openPlan();
$('#plan-back').onclick = () => openMain('settings');
$('#plan-subscribe').onclick = () => subscribePlan();
$('#plan-cancel').onclick = () => cancelPlan();

// 결제창에서 돌아온 경우 (?billing=success&authKey=...&customerKey=...)
async function handleBillingReturn() {
  const p = new URLSearchParams(location.search);
  const b = p.get('billing');
  if (!b) return;
  history.replaceState(null, '', location.pathname);
  if (b === 'fail') return alert('결제가 완료되지 않았습니다' + (p.get('message') ? ': ' + p.get('message') : ''));
  try {
    await api('/api/billing/issue', {
      method: 'POST',
      body: JSON.stringify({ authKey: p.get('authKey'), customerKey: p.get('customerKey') }),
    });
    alert('프리미엄 구독이 시작되었습니다.');
    await openPlan();
  } catch (e) {
    alert(e.message);
  }
}

// ===== 방해 금지 시간 / 대화방 알림 끄기 =====
const mutedKeys = new Set(); // 'dm:12' 또는 'group:3'

async function loadMutes() {
  const list = await api('/api/prefs/mutes');
  mutedKeys.clear();
  for (const m of list) mutedKeys.add(m.kind + ':' + m.id);
}

function renderMuteBtn() {
  if (!current) return;
  $('#btn-mute').textContent = mutedKeys.has(current.type + ':' + current.id) ? '알림 켜기' : '알림 끄기';
}

$('#btn-mute').onclick = async () => {
  if (!current) return;
  const key = current.type + ':' + current.id;
  const muted = !mutedKeys.has(key);
  try {
    await api('/api/prefs/mutes', { method: 'PUT', body: JSON.stringify({ kind: current.type, id: current.id, muted }) });
    if (muted) mutedKeys.add(key);
    else mutedKeys.delete(key);
    renderMuteBtn();
  } catch (e) {
    alert(e.message);
  }
};

function fillHours(sel) {
  sel.innerHTML = '';
  for (let h = 0; h < 24; h++) {
    const o = document.createElement('option');
    o.value = h;
    o.textContent = String(h).padStart(2, '0') + ':00';
    sel.append(o);
  }
}

async function openQuiet() {
  fillHours($('#quiet-from'));
  fillHours($('#quiet-to'));
  $('#quiet-msg').textContent = '';
  showView('quiet');
  try {
    const q = await api('/api/prefs/quiet');
    $('#quiet-on').checked = !!q.on;
    $('#quiet-from').value = q.from;
    $('#quiet-to').value = q.to;
  } catch (e) {
    $('#quiet-msg').textContent = e.message;
  }
}

$('#btn-quiet').onclick = () => openQuiet();
$('#quiet-back').onclick = () => openMain('settings');
$('#quiet-save').onclick = async () => {
  try {
    await api('/api/prefs/quiet', {
      method: 'PUT',
      body: JSON.stringify({ on: $('#quiet-on').checked, from: Number($('#quiet-from').value), to: Number($('#quiet-to').value) }),
    });
    $('#quiet-msg').textContent = '저장했습니다.';
  } catch (e) {
    $('#quiet-msg').textContent = e.message;
  }
};

// ===== 그룹 게시판 (목적 템플릿 · 공지 · 일정, 방장만 작성) =====
const PURPOSE_LABEL = { general: '일반 그룹', parents: '학부모 모임', club: '동호회', guild: '게임 길드', study: '스터디' };
let boardState = null;

// 암호화 그룹이면 그룹 키로 열고, 아니면 그대로 보여줌
async function openBoardText(gid, enc, epoch, body) {
  if (!enc) return body;
  let k = await groupKey(gid, epoch);
  if (!k) {
    await syncGroupKeys(gid).catch(() => {});
    k = await groupKey(gid, epoch);
  }
  if (!k) return '(암호화된 내용을 열 수 없습니다)';
  try {
    return (await E2EE.open(k, body)).t;
  } catch (_) {
    return '(암호화된 내용을 열 수 없습니다)';
  }
}

// 작성 내용을 그룹 키로 암호화 (일반 그룹이면 평문)
async function sealBoardText(text) {
  const sk = await sendKey();
  if (!sk) return { body: text, epoch: null };
  return { body: await E2EE.seal(sk.key, { t: text }), epoch: sk.epoch };
}

async function refreshBoard(gid) {
  if (!current || current.type !== 'group' || current.id !== gid) return;
  try {
    boardState = await api('/api/groups/' + gid + '/board');
  } catch (_) {
    return;
  }
  const notice = boardState.notice ? await openBoardText(gid, boardState.enc, boardState.notice_epoch, boardState.notice) : '';
  $('#notice-text').textContent = notice ? '📌 공지 · ' + notice : '';
  $('#notice-banner').hidden = !notice;
  if (!$('#view-gboard').hidden) await renderBoard();
}

async function renderBoard() {
  const s = boardState;
  if (!s || !current || current.type !== 'group') return;
  const gid = current.id;
  $('#gb-title').textContent = current.name + ' 게시판';
  $('#gb-purpose').textContent = PURPOSE_LABEL[s.purpose] || '일반 그룹';
  $('#gb-notice').textContent = s.notice
    ? await openBoardText(gid, s.enc, s.notice_epoch, s.notice)
    : '등록된 공지가 없습니다';
  $('#gb-notice-form').hidden = !s.owner;
  $('#gb-event-form').hidden = !s.owner;
  const ul = $('#gb-events');
  ul.innerHTML = '';
  if (!s.events.length) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = '예정된 일정이 없습니다';
    ul.appendChild(li);
  }
  for (const ev of s.events) {
    const li = document.createElement('li');
    const text = await openBoardText(gid, s.enc, ev.epoch, ev.body);
    const when = new Date(ev.starts_at).toLocaleString('ko-KR', { dateStyle: 'short', timeStyle: 'short' });
    const span = document.createElement('span');
    span.textContent = when + ' · ' + text;
    li.appendChild(span);
    if (s.owner) {
      const del = document.createElement('button');
      del.type = 'button';
      del.className = 'ghost small-btn';
      del.textContent = '삭제';
      del.onclick = async () => {
        try {
          await api('/api/groups/' + gid + '/events/' + ev.id, { method: 'DELETE' });
          await refreshBoard(gid);
        } catch (e) {
          $('#gb-msg').textContent = e.message;
        }
      };
      li.appendChild(del);
    }
    ul.appendChild(li);
  }
}

async function openBoard() {
  if (!current || current.type !== 'group') return;
  $('#gb-msg').textContent = '';
  showView('gboard');
  await refreshBoard(current.id);
}
$('#btn-board').onclick = () => openBoard();
$('#gb-back').onclick = () => {
  showView('main');
  setChatOpen(true);
};

$('#gb-notice-form').onsubmit = async (e) => {
  e.preventDefault();
  const text = $('#gb-notice-text').value.trim();
  if (!text || !current) return;
  try {
    const sealed = await sealBoardText(text);
    await api('/api/groups/' + current.id + '/notice', { method: 'PUT', body: JSON.stringify(sealed) });
    $('#gb-notice-text').value = '';
    $('#gb-msg').textContent = '공지를 저장했습니다.';
    await refreshBoard(current.id);
  } catch (err) {
    $('#gb-msg').textContent = err.message;
  }
};

$('#gb-event-form').onsubmit = async (e) => {
  e.preventDefault();
  const title = $('#gb-event-title').value.trim();
  const when = $('#gb-event-time').value;
  if (!title || !when || !current) return;
  try {
    const sealed = await sealBoardText(title);
    await api('/api/groups/' + current.id + '/events', {
      method: 'POST',
      body: JSON.stringify({ body: sealed.body, epoch: sealed.epoch, startsAt: new Date(when).toISOString() }),
    });
    $('#gb-event-title').value = '';
    $('#gb-event-time').value = '';
    $('#gb-msg').textContent = '일정을 추가했습니다.';
    await refreshBoard(current.id);
  } catch (err) {
    $('#gb-msg').textContent = err.message;
  }
};

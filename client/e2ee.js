// 종단간 암호화(E2EE) 도우미 - 브라우저 WebCrypto 사용
// - 계정마다 ECDH(P-256) 키 쌍을 만듭니다.
// - 개인키는 비밀번호에서 만든 키(PBKDF2 + AES-GCM)로 감싸서 서버에 저장합니다. 서버는 풀 수 없습니다.
// - 두 사람의 공개키로 공유 비밀키(AES-GCM 256)를 만들어 메시지를 암호화합니다.
const E2EE = (() => {
  const te = new TextEncoder();
  const td = new TextDecoder();
  const ITER = 200000;
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

  const toB64 = (u8) => {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  };
  const fromB64 = (b64) => {
    const raw = atob(b64);
    const u8 = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) u8[i] = raw.charCodeAt(i);
    return u8;
  };
  const concat = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  };

  async function wrapKeyFromPassword(password, salt, iter) {
    const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // 개인키(PKCS8 바이트)를 비밀번호로 감싸서 JSON 문자열로 만듭니다
  async function wrapPrivate(password, pkcs8) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await wrapKeyFromPassword(password, salt, ITER);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pkcs8));
    return JSON.stringify({ v: 1, iter: ITER, salt: toB64(salt), iv: toB64(iv), ct: toB64(ct) });
  }

  async function unwrapPrivate(password, blob) {
    const b = JSON.parse(blob);
    const key = await wrapKeyFromPassword(password, fromB64(b.salt), b.iter);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(b.iv) }, key, fromB64(b.ct));
    return new Uint8Array(pt);
  }

  async function importPrivate(pkcs8) {
    return crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveKey']);
  }

  // 새 키 쌍 생성. password가 없으면(카카오 등) 서버 백업 없이 이 기기에만 저장됩니다.
  async function createIdentity(password) {
    const pair = await crypto.subtle.generateKey(ECDH, true, ['deriveKey']);
    const pubSpki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const blob = password ? await wrapPrivate(password, pkcs8) : null;
    const privKey = await importPrivate(pkcs8);
    return { pubB64: toB64(pubSpki), blob, privKey };
  }

  // 서버에 저장된 감싼 개인키를 비밀번호로 풀어 사용할 수 있는 키로 만듭니다
  async function unlockIdentity(password, blob) {
    return importPrivate(await unwrapPrivate(password, blob));
  }

  // 비밀번호를 바꿀 때: 옛 비밀번호로 풀고 새 비밀번호로 다시 감쌉니다
  async function rewrap(oldPassword, blob, newPassword) {
    return wrapPrivate(newPassword, await unwrapPrivate(oldPassword, blob));
  }

  // 상대 공개키와 내 개인키로 두 사람만 아는 AES 키를 만듭니다
  async function sharedKey(privKey, peerPubB64) {
    const pub = await crypto.subtle.importKey('spki', fromB64(peerPubB64), ECDH, true, []);
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: pub },
      privKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // JSON 객체 암호화 -> base64 문자열 (iv + 암호문)
  async function seal(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj))));
    return toB64(concat(iv, ct));
  }

  async function open(key, b64) {
    const u8 = fromB64(b64);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, key, u8.slice(12));
    return JSON.parse(td.decode(pt));
  }

  // 파일 바이트 암호화: iv(base64)와 암호문(Uint8Array)을 돌려줍니다
  async function sealBytes(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
    return { iv: toB64(iv), data: ct };
  }

  async function openBytes(key, ivB64, data) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, data);
  }

  // ----- 이 기기에 개인키 보관 (IndexedDB) -----
  const DB_NAME = 'e2ee-keys';
  function openDb() {
    return new Promise((res, rej) => {
      const r = indexedDB.open(DB_NAME, 1);
      r.onupgradeneeded = () => r.result.createObjectStore('keys');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  }
  async function saveLocal(userId, privKey, pubB64) {
    const db = await openDb();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').put({ priv: privKey, pub: pubB64 }, String(userId));
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  }
  async function loadLocal(userId) {
    const db = await openDb();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readonly');
      const rq = tx.objectStore('keys').get(String(userId));
      rq.onsuccess = () => res(rq.result || null);
      rq.onerror = () => rej(rq.error);
    });
  }

  // ----- 그룹 키 (세대별 랜덤 AES 키) -----
  const genRaw = () => crypto.getRandomValues(new Uint8Array(32));
  const importRawKey = (raw) => crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  // 그룹 키(raw)를 공유 키로 감싸서 문자열로 / 풀어서 raw로
  const wrapRaw = (shared, raw) => seal(shared, { k: toB64(raw) });
  async function unwrapRaw(shared, wrapped) { return fromB64((await open(shared, wrapped)).k); }

  // 문자열 값을 이 기기에 저장 (그룹 키 등)
  async function saveKV(name, value) {
    const db = await openDb();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').put(value, name);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  }
  async function loadKV(name) {
    const db = await openDb();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readonly');
      const rq = tx.objectStore('keys').get(name);
      rq.onsuccess = () => res(rq.result === undefined ? null : rq.result);
      rq.onerror = () => rej(rq.error);
    });
  }

  return {
    createIdentity, unlockIdentity, rewrap, sharedKey,
    seal, open, sealBytes, openBytes,
    saveLocal, loadLocal,
    toB64, fromB64, genRaw, importRawKey, wrapRaw, unwrapRaw, saveKV, loadKV,
  };
})();

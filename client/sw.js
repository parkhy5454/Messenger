const CACHE = 'messenger-v51';
const SHELL = ['/', '/index.html', '/style.css', '/e2ee.js', '/kakao.js', '/ics.js', '/vendor/jszip.min.js', '/app.js', '/manifest.json', '/icon-192.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(self.clients.claim());
});

// 화면 파일만 캐시합니다. API와 실시간 연결은 캐시하지 않습니다.
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.pathname.startsWith('/api/') || url.pathname.startsWith('/socket.io/')) return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});

// 푸시 알림 수신: 앱이 꺼져 있어도 기기 알림으로 표시합니다
self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch { data = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(data.title || '메신저', {
    body: data.body || '새 메시지가 도착했습니다',
    tag: data.tag || 'messenger',
    renotify: true,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: { url: data.url || '/' },
  }));
});

// 알림을 누르면 앱 창을 열거나 앞으로 가져옵니다
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if ('focus' in c) return c.focus();
      }
      return self.clients.openWindow(url);
    })
  );
});

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  async function load() {
    const box = document.getElementById('incidents');
    try {
      const r = await fetch('/api/status', { cache: 'no-store' });
      const s = await r.json();
      const st = document.getElementById('state');
      st.textContent = s.ok ? '정상 운영 중' : '점검이 필요합니다';
      st.className = 'state ' + (s.ok ? 'ok' : 'bad');
      renderHistory(s.history);
      document.getElementById('detail').textContent =
        '데이터베이스 ' + (s.db === 'ok' ? '정상' : '오류') + ' · 응답 ' + s.latency_ms + 'ms · 확인 ' +
        new Date(s.checked_at).toLocaleString('ko-KR');
      if (!s.incidents.length) {
        box.innerHTML = '<p class="muted">기록된 장애가 없습니다.</p>';
      } else {
        box.innerHTML = s.incidents.map((i) =>
          '<div class="inc"><div><b>' + esc(i.date) + '</b> · ' + esc(i.title) + ' <span class="muted">' +
          (i.resolved ? '(해결됨)' : '(조치 중)') + '</span></div>' +
          (i.detail ? '<div class="muted">' + esc(i.detail) + '</div>' : '') + '</div>').join('');
      }
    } catch (e) {
      document.getElementById('state').textContent = '상태를 확인할 수 없습니다';
      document.getElementById('state').className = 'state bad';
    }
  }
  function renderHistory(h) {
    const bars = document.getElementById('bars');
    const label = document.getElementById('uptime30');
    if (!h) { bars.innerHTML = ''; label.textContent = '· 기록을 불러오지 못했습니다'; return; }
    label.textContent = h.uptime30 == null ? '' : '· 30일 가용률 ' + h.uptime30 + '%';
    bars.innerHTML = h.days.map((d) => {
      const cls = d.uptime == null ? '' : d.uptime >= 99.9 ? 'ok' : d.uptime >= 99 ? 'warn' : 'bad';
      const title = d.date + ' · ' + (d.uptime == null ? '측정 기록 없음' : d.uptime + '% (측정 ' + d.samples + '회)');
      return '<div class="bar ' + cls + '" title="' + esc(title) + '"></div>';
    }).join('');
  }
  load();
  setInterval(load, 60000);

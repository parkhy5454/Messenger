// 카카오톡 대화 내보내기(.txt) 읽기. 파일은 서버로 보내지 않고 이 기기에서만 처리합니다.
const KakaoImport = (() => {
  // 예: 2026. 10. 15. 오후 3:00, 홍길동 : 안녕하세요   (새 형식: 2026년 10월 15일 오후 3:00, ...)
  const LINE = /^(\d{4})\s*[.년]\s*(\d{1,2})\s*[.월]\s*(\d{1,2})\s*[.일]?\.?\s*(오전|오후)\s*(\d{1,2}):(\d{2})\s*,\s*(.+?)\s*:\s?(.*)$/;
  const DAY_SEP = /^-{3,}.*-{3,}\s*$/;

  function toDate(y, mo, d, ap, h, mi) {
    let hh = Number(h) % 12; // 오전 12시 = 0시, 오후 12시 = 12시
    if (ap === '오후') hh += 12;
    return new Date(Number(y), Number(mo) - 1, Number(d), hh, Number(mi));
  }

  function parse(text) {
    const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    let title = '';
    let saved = '';
    const messages = [];
    let blanks = 0;
    for (const line of lines) {
      if (!title && /^카카오톡 대화/.test(line)) {
        title = line.replace(/^카카오톡 대화(방)?\s*:\s*/, '').trim();
        continue;
      }
      if (!saved && /^저장한 날짜/.test(line)) {
        saved = line.replace(/^저장한 날짜\s*:\s*/, '').trim();
        continue;
      }
      if (DAY_SEP.test(line)) { blanks = 0; continue; }
      const m = LINE.exec(line);
      if (m) {
        blanks = 0;
        messages.push({
          at: toDate(m[1], m[2], m[3], m[4], m[5], m[6]).toISOString(),
          from: m[7],
          text: m[8],
        });
        continue;
      }
      if (line === '') { blanks += 1; continue; }
      // 여러 줄 메시지의 이어진 줄 (첫 메시지 앞의 줄은 버림)
      if (messages.length) {
        const last = messages[messages.length - 1];
        last.text += '\n'.repeat(blanks) + '\n' + line;
        blanks = 0;
      }
    }
    for (const m of messages) m.text = m.text.replace(/\s+$/, '');
    return { title: title || '카톡 대화', saved, messages };
  }

  return { parse };
})();

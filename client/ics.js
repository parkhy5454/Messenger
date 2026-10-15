// 일정을 캘린더 파일(.ics)로 만듭니다. 구글·애플·네이버 캘린더 등에서 열 수 있습니다.
const ICS = (() => {
  const enc = new TextEncoder();
  const esc = (s) => String(s == null ? '' : s)
    .replace(/\\/g, '\\\\').replace(/;/g, '\;').replace(/,/g, '\\,').replace(/\r\n|\r|\n/g, '\\n');
  // RFC 5545: 한 줄은 75옥텟을 넘기지 않게 접고, 이어지는 줄은 공백으로 시작
  function fold(line) {
    const parts = [];
    let cur = '';
    let bytes = 0;
    for (const ch of line) {
      const n = enc.encode(ch).length;
      const limit = parts.length === 0 ? 75 : 74;
      if (bytes + n > limit) {
        parts.push(cur);
        cur = '';
        bytes = 0;
      }
      cur += ch;
      bytes += n;
    }
    parts.push(cur);
    return parts.join('\r\n ');
  }
  const stamp = (d) => d.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  function build({ uid, title, start, end, desc, now = new Date() }) {
    const lines = [
      'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Messenger//KR', 'CALSCALE:GREGORIAN',
      'BEGIN:VEVENT',
      'UID:' + uid,
      'DTSTAMP:' + stamp(now),
      'DTSTART:' + stamp(start),
      'DTEND:' + stamp(end),
      'SUMMARY:' + esc(title),
      'DESCRIPTION:' + esc(desc || ''),
      'END:VEVENT',
      'END:VCALENDAR',
    ];
    return lines.map(fold).join('\r\n') + '\r\n';
  }
  return { build, esc, fold };
})();

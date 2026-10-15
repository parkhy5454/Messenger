// 간단한 메모리 기반 요청 횟수 제한 (단일 인스턴스용)
// limit({ windowMs, max, key }) : key(req) 로 묶어서 windowMs 동안 max 번까지만 허용
const hits = new Map();

function limit({ windowMs, max, key }) {
  return (req, res, next) => {
    const k = key ? key(req) : req.ip;
    const now = Date.now();
    let h = hits.get(k);
    if (!h || now > h.reset) {
      h = { count: 0, reset: now + windowMs };
      hits.set(k, h);
    }
    h.count += 1;
    if (h.count > max) {
      const sec = Math.ceil((h.reset - now) / 1000);
      res.set('Retry-After', String(sec));
      return res.status(429).json({ error: '요청이 너무 많습니다. 잠시 후 다시 시도하세요' });
    }
    next();
  };
}

// 만료된 항목 정리 (메모리 누수 방지)
setInterval(() => {
  const now = Date.now();
  for (const [k, h] of hits) if (now > h.reset) hits.delete(k);
}, 10 * 60 * 1000).unref();

module.exports = { limit };

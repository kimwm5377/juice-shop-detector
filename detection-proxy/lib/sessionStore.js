const crypto = require("crypto");

// 세션 단위 데이터: 요청 로그 + 클라이언트 텔레메트리
const sessions = new Map();
// IP 단위 데이터: 세션이 자꾸 바뀌는(쿠키 미보존) 스크립트형 공격 탐지용
const ipIndex = new Map();

const MAX_REQUESTS_PER_SESSION = 500; // 메모리 보호용 링버퍼 상한

function headerFingerprint(headers) {
  const relevant = [
    headers["user-agent"] || "",
    headers["accept"] || "",
    headers["accept-language"] || "",
    headers["accept-encoding"] || "",
  ].join("|");
  return crypto.createHash("sha1").update(relevant).digest("hex").slice(0, 12);
}

function getOrCreateSession(sessionId, ip) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      id: sessionId,
      ip,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      requests: [], // { ts, method, url, status }
      headerSample: null,
      fingerprint: null,
      userAgent: null,
      telemetry: {
        mouseMoveCount: 0,
        scrollCount: 0,
        domEventTypes: new Set(),
        pageLoads: 0,
        lastTelemetryAt: null,
      },
    });
  }
  const s = sessions.get(sessionId);
  s.lastSeen = Date.now();
  return s;
}

const MAX_BODY_LOG_CHARS = 2000; // 요청 로그에 남기는 body 최대 길이 (메모리 보호)

function truncateBody(body) {
  if (body === undefined || body === null) return undefined;
  // body-parser는 body가 없는 요청(GET 등)에도 기본값 {}를 넣어주므로 빈 객체는 제외
  if (typeof body === "object" && Object.keys(body).length === 0) return undefined;
  const str = typeof body === "string" ? body : JSON.stringify(body);
  if (!str) return undefined;
  return str.length > MAX_BODY_LOG_CHARS ? str.slice(0, MAX_BODY_LOG_CHARS) + "…(truncated)" : str;
}

function recordRequest(sessionId, ip, { method, url, status, headers, body, tags }) {
  const s = getOrCreateSession(sessionId, ip);

  if (!s.headerSample) {
    s.headerSample = headers;
    s.fingerprint = headerFingerprint(headers);
    s.userAgent = headers["user-agent"] || "";
  }

  s.requests.push({
    ts: Date.now(),
    method,
    url,
    status,
    body: truncateBody(body),
    tags: tags || [],
  });
  if (s.requests.length > MAX_REQUESTS_PER_SESSION) {
    s.requests.shift();
  }

  // IP(행위자) 인덱스 업데이트 - 세션 churn 감지 + 행위자 단위 집계 분석용.
  // 공격자가 세션 쿠키를 보존하지 않고 요청을 흩뿌려도, IP 단위로 요청을 모아
  // 볼륨/행동 feature를 계산할 수 있게 요청 레코드 자체를 여기에도 축적한다.
  if (!ipIndex.has(ip)) {
    ipIndex.set(ip, { sessionIds: new Set(), requestTimestamps: [], requests: [] });
  }
  const ipEntry = ipIndex.get(ip);
  ipEntry.sessionIds.add(sessionId);
  ipEntry.requestTimestamps.push(Date.now());
  ipEntry.requests.push({ ts: Date.now(), url, status, tags: tags || [] });
  if (ipEntry.requestTimestamps.length > MAX_REQUESTS_PER_SESSION * 2) {
    ipEntry.requestTimestamps.shift();
  }
  if (ipEntry.requests.length > MAX_REQUESTS_PER_SESSION * 2) {
    ipEntry.requests.shift();
  }

  return s;
}

function recordTelemetry(sessionId, ip, payload) {
  const s = getOrCreateSession(sessionId, ip);
  const t = s.telemetry;
  t.mouseMoveCount += payload.mouseMoveCount || 0;
  t.scrollCount += payload.scrollCount || 0;
  (payload.domEventTypes || []).forEach((ev) => t.domEventTypes.add(ev));
  t.pageLoads += payload.pageLoad ? 1 : 0;
  t.lastTelemetryAt = Date.now();
  return s;
}

function getSession(sessionId) {
  return sessions.get(sessionId);
}

function getAllSessions() {
  return Array.from(sessions.values());
}

function getIpEntry(ip) {
  return ipIndex.get(ip);
}

module.exports = {
  getOrCreateSession,
  recordRequest,
  recordTelemetry,
  getSession,
  getAllSessions,
  getIpEntry,
  headerFingerprint,
};

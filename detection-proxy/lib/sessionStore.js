const crypto = require("crypto");
const { normalizePath } = require("./requestMetadata");

// 세션 단위 데이터: 요청 로그 + 클라이언트 텔레메트리
const sessions = new Map();
// IP + HTTP 헤더 fingerprint 단위 행위자 그룹.
// Docker/NAT 환경에서 IP만으로 서로 다른 브라우저와 CLI를 합치지 않도록 분리한다.
const actors = new Map();
// 동일 Authorization Bearer Token의 SHA-256 hash 단위 요청 그룹
const authGroups = new Map();
// 동일 IP 전체 트래픽 관찰용. NAT/Docker에서 여러 클라이언트가 섞일 수 있어 점수/차단에 쓰지 않는다.
const ipEntries = new Map();

const MAX_REQUESTS_PER_SESSION = 500; // 메모리 보호용 링버퍼 상한
const MAX_REQUESTS_PER_AUTH_GROUP = MAX_REQUESTS_PER_SESSION * 2;
const MAX_REQUESTS_PER_IP_ENTRY = MAX_REQUESTS_PER_SESSION * 2;

const SENSITIVE_DETECTION_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-experiment-run-id",
]);

function emptyAttackHistory() {
  return {
    hasAttackHistory: false,
    maxAttackScore: 0,
    maxCrsAnomalyScore: 0,
    cumulativeRuleHits: 0,
    matchedRuleIds: [],
    attackCategories: [],
    firstAttackAt: null,
    lastAttackAt: null,
  };
}

function addUnique(target, values) {
  const existing = new Set(target);
  for (const value of values || []) {
    if (value === undefined || value === null || value === "") continue;
    existing.add(String(value));
  }
  target.splice(0, target.length, ...existing);
}

function recordCrsAttackHistory(entity, attackDetection, timestamp) {
  if (!entity || !attackDetection?.available || !attackDetection.ruleHitCount) return false;
  const history = entity.attackHistory || (entity.attackHistory = emptyAttackHistory());
  history.hasAttackHistory = true;
  history.cumulativeRuleHits += Number(attackDetection.ruleHitCount) || 0;
  history.maxCrsAnomalyScore = Math.max(
    history.maxCrsAnomalyScore,
    Number(attackDetection.anomalyScore) || 0
  );
  addUnique(history.matchedRuleIds, (attackDetection.hits || []).map((hit) => hit.ruleId));
  addUnique(history.attackCategories, attackDetection.categories);
  if (history.firstAttackAt === null) history.firstAttackAt = timestamp;
  history.lastAttackAt = timestamp;
  return true;
}

function updateMaxAttackScore(entity, score) {
  if (!entity || !Number.isFinite(score)) return;
  const history = entity.attackHistory || (entity.attackHistory = emptyAttackHistory());
  history.maxAttackScore = Math.max(history.maxAttackScore, score);
}

function withoutSensitiveHeaders(headers = {}) {
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !SENSITIVE_DETECTION_HEADERS.has(name.toLowerCase())
    )
  );
}

const withoutAuthorizationHeaders = withoutSensitiveHeaders;

function headerFingerprint(headers) {
  const relevant = [
    headers["user-agent"] || "",
    headers["accept"] || "",
    headers["accept-language"] || "",
    headers["accept-encoding"] || "",
  ].join("|");
  return crypto.createHash("sha1").update(relevant).digest("hex").slice(0, 12);
}

function deriveActorId(ip, fingerprint) {
  const digest = crypto
    .createHash("sha256")
    .update(`${ip}\u0000${fingerprint}`)
    .digest("hex")
    .slice(0, 24);
  return `actor:${digest}`;
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
      actorId: null,
      actorIds: new Set(),
      userAgent: null,
      attackHistory: emptyAttackHistory(),
      telemetry: {
        mouseMoveCount: 0,
        scrollCount: 0,
        routeChangeCount: 0,
        domEventTypes: new Set(),
        pageLoads: 0,
        currentUrl: null,
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

function recordRequest(
  sessionId,
  ip,
  {
    method,
    url,
    status,
    headers = {},
    body,
    tags,
    authGroupId,
    normalizedPath: suppliedNormalizedPath,
    payloadFingerprint = null,
    hasAuthorization,
    experimentRunId = null,
    requestContentType = null,
    requestContentLength = null,
    requestBodyBytes = null,
    responseContentType = null,
    responseContentLength = null,
    responseBodyBytes = null,
    attackDetection = null,
    ts,
  }
) {
  const s = getOrCreateSession(sessionId, ip);
  const now = Number.isFinite(ts) ? ts : Date.now();
  const fingerprint = headerFingerprint(headers);
  const actorId = deriveActorId(ip, fingerprint);
  const normalizedPath = suppliedNormalizedPath || normalizePath(url);
  const normalizedMethod = String(method || "GET").toUpperCase();
  const operation = `${normalizedMethod} ${normalizedPath}`;
  const requestHasAuthorization =
    typeof hasAuthorization === "boolean" ? hasAuthorization : Boolean(headers.authorization);

  if (!s.headerSample) {
    // 분류에 필요한 헤더 특성은 유지하되 자격 증명은 저장하지 않는다.
    s.headerSample = withoutSensitiveHeaders(headers);
    s.fingerprint = fingerprint;
    s.actorId = actorId;
    s.userAgent = headers["user-agent"] || "";
  }
  s.actorIds.add(actorId);
  s.lastSeen = now;

  const requestRecord = {
    ts: now,
    method: normalizedMethod,
    url,
    normalizedPath,
    operation,
    status,
    sessionId,
    actorId,
    authGroupId: authGroupId || null,
    payloadFingerprint,
    hasAuthorization: requestHasAuthorization,
    experimentRunId: experimentRunId || null,
    requestContentType,
    requestContentLength,
    requestBodyBytes,
    responseContentType,
    responseContentLength,
    responseBodyBytes,
    attackDetection,
    body: truncateBody(body),
    tags: tags || [],
  };
  s.requests.push(requestRecord);
  if (s.requests.length > MAX_REQUESTS_PER_SESSION) {
    s.requests.shift();
  }

  if (authGroupId) {
    if (!authGroups.has(authGroupId)) {
      authGroups.set(authGroupId, {
        id: authGroupId,
        firstSeen: now,
        lastSeen: now,
        totalRequests: 0,
        sessionIds: new Set(),
        actorIds: new Set(),
        requests: [],
        attackHistory: emptyAttackHistory(),
      });
    }
    const authGroup = authGroups.get(authGroupId);
    authGroup.lastSeen = now;
    authGroup.totalRequests++;
    authGroup.sessionIds.add(sessionId);
    authGroup.actorIds.add(actorId);
    authGroup.requests.push({ ...requestRecord });
    if (authGroup.requests.length > MAX_REQUESTS_PER_AUTH_GROUP) {
      authGroup.requests.shift();
    }
  }

  // 같은 IP에서도 브라우저/CLI fingerprint가 다르면 별도 Actor로 취급한다.
  // 동일 fingerprint가 dlsid를 계속 바꾸는 경우에만 요청과 churn을 합산한다.
  if (!actors.has(actorId)) {
    actors.set(actorId, {
      id: actorId,
      ip,
      fingerprint,
      headerSample: withoutSensitiveHeaders(headers),
      userAgent: headers["user-agent"] || "",
      firstSeen: now,
      lastSeen: now,
      totalRequests: 0,
      sessionIds: new Set(),
      requests: [],
      attackHistory: emptyAttackHistory(),
    });
  }
  const actor = actors.get(actorId);
  actor.lastSeen = now;
  actor.totalRequests++;
  actor.sessionIds.add(sessionId);
  actor.requests.push({ ...requestRecord });
  if (actor.requests.length > MAX_REQUESTS_PER_SESSION * 2) {
    actor.requests.shift();
  }

  if (!ipEntries.has(ip)) {
    ipEntries.set(ip, {
      ip,
      firstSeen: now,
      lastSeen: now,
      totalRequests: 0,
      sessionIds: new Set(),
      actorIds: new Set(),
      requests: [],
    });
  }
  const ipEntry = ipEntries.get(ip);
  ipEntry.lastSeen = now;
  ipEntry.totalRequests++;
  ipEntry.sessionIds.add(sessionId);
  ipEntry.actorIds.add(actorId);
  ipEntry.requests.push({ ...requestRecord });
  if (ipEntry.requests.length > MAX_REQUESTS_PER_IP_ENTRY) ipEntry.requests.shift();

  // 최근 요청 링버퍼와 별도로 CRS가 확인한 공격 규칙 이력을 누적한다.
  // legacy 정규식 fallback은 CRS 결과와 섞이지 않도록 누적 이력에서 제외한다.
  recordCrsAttackHistory(s, attackDetection, now);
  recordCrsAttackHistory(actor, attackDetection, now);
  if (authGroupId) recordCrsAttackHistory(authGroups.get(authGroupId), attackDetection, now);

  return s;
}

function updateAttackScoreHistory({ sessionId, actorId, authGroupId, scores = {} }) {
  updateMaxAttackScore(sessions.get(sessionId), scores.session);
  updateMaxAttackScore(actors.get(actorId), scores.actor);
  if (authGroupId) updateMaxAttackScore(authGroups.get(authGroupId), scores.authGroup);
}

function recordTelemetry(sessionId, ip, payload) {
  const s = getOrCreateSession(sessionId, ip);
  const t = s.telemetry;
  t.mouseMoveCount += payload.mouseMoveCount || 0;
  t.scrollCount += payload.scrollCount || 0;
  t.routeChangeCount += payload.routeChangeCount || 0;
  (payload.domEventTypes || []).forEach((ev) => t.domEventTypes.add(ev));
  t.pageLoads += payload.pageLoad ? 1 : 0;
  if (typeof payload.url === "string") t.currentUrl = payload.url.slice(0, 2048);
  t.lastTelemetryAt = Date.now();
  return s;
}

function getSession(sessionId) {
  return sessions.get(sessionId);
}

function getAllSessions() {
  return Array.from(sessions.values());
}

function getAllActors() {
  return Array.from(actors.values());
}

function getActor(actorId) {
  return actors.get(actorId);
}

function getAllAuthGroups() {
  return Array.from(authGroups.values());
}

function getAuthGroup(authGroupId) {
  return authGroups.get(authGroupId);
}

function getAllIpEntries() {
  return Array.from(ipEntries.values());
}

function getIpEntry(ip) {
  return ipEntries.get(ip);
}

module.exports = {
  getOrCreateSession,
  recordRequest,
  recordTelemetry,
  getSession,
  getAllSessions,
  getAllActors,
  getActor,
  getAllAuthGroups,
  getAuthGroup,
  getAllIpEntries,
  getIpEntry,
  updateAttackScoreHistory,
  emptyAttackHistory,
  headerFingerprint,
  deriveActorId,
  withoutSensitiveHeaders,
  withoutAuthorizationHeaders,
};

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const {
  createProxyMiddleware,
  responseInterceptor,
  fixRequestBody,
} = require("http-proxy-middleware");
const { v4: uuidv4 } = require("uuid");

const store = require("./lib/sessionStore");
const { deriveAuthGroupId } = require("./lib/authGroup");
const {
  extractFeatures,
  extractActorFeatures,
  extractAuthGroupFeatures,
  extractIpFeatures,
} = require("./lib/featureExtractor");
const { classify } = require("./lib/classifier");
const { tagPayload } = require("./lib/payloadSignatures");
const {
  createPayloadFingerprint,
  sanitizeExperimentRunId,
  sanitizeMetadataHeaderValue,
  parseContentLength,
} = require("./lib/requestMetadata");
const {
  computeAgenticEvidence,
  computePartitionedAgenticEvidence,
} = require("./lib/agenticEvidence");
const { CrsScanner } = require("./lib/crsScanner");

const PORT = process.env.PORT || 8080;
const TARGET = process.env.TARGET_URL || process.env.JUICE_SHOP_URL || "http://localhost:3000";
const BLOCK_MODE = process.env.BLOCK_MODE === "true";
const LOG_THRESHOLD = parseFloat(process.env.BLOCK_THRESHOLD || "0.75");
const ENABLE_EXPERIMENT_RUN_ID = process.env.ENABLE_EXPERIMENT_RUN_ID === "true";
const EXPERIMENT_RUN_HEADER = "x-experiment-run-id";
const configuredPayloadFingerprintKey = process.env.PAYLOAD_FINGERPRINT_KEY;
const PAYLOAD_FINGERPRINT_KEY = configuredPayloadFingerprintKey || crypto.randomBytes(32);

const SESSION_COOKIE = "dlsid";
const crsScanner = new CrsScanner();

const app = express();
app.disable("x-powered-by");
app.use(cookieParser());

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function analyzeSession(session) {
  const features = extractFeatures(session);
  return {
    ...classify(features),
    features,
    agenticEvidence: computeAgenticEvidence(session.requests),
  };
}

function analyzeActor(actor) {
  const features = extractActorFeatures(actor, store.getSession);
  return {
    ...classify(features),
    features,
    agenticEvidence: computeAgenticEvidence(actor.requests),
  };
}

function analyzeAuthGroup(group) {
  const features = extractAuthGroupFeatures(group, store.getSession);
  return {
    ...classify(features),
    features,
    // 동일 token을 공유하는 서로 다른 Actor의 transition은 연결하지 않는다.
    agenticEvidence: computePartitionedAgenticEvidence(group.requests),
  };
}

// 세션 쿠키 부여 (없으면 새로 발급)
app.use((req, res, next) => {
  let sid = req.cookies[SESSION_COOKIE];
  if (!sid) {
    sid = uuidv4();
    res.cookie(SESSION_COOKIE, sid, { httpOnly: false, sameSite: "lax" });
  }
  req.detectionSessionId = sid;
  next();
});

// --- 탐지 레이어 자체 엔드포인트들 (프록시보다 먼저 매칭) ---
app.use("/__detection/static", express.static(require("path").join(__dirname, "public")));

app.get("/__detection/dashboard", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "dashboard.html"));
});

function captureParsedBodyBytes(req, _res, buffer) {
  req.detectionRequestBodyBytes = buffer.length;
  req.detectionRequestBodyBuffer = Buffer.from(buffer);
}

// JSON / urlencoded body만 파싱 (multipart, 바이너리 등은 그대로 통과되어 스트림이 안 깨짐).
// 파싱된 body는 onProxyReq에서 fixRequestBody()로 다시 스트림에 실어 juice-shop으로 전달한다.
app.use(express.json({ limit: "5mb", verify: captureParsedBodyBytes }));
app.use(express.urlencoded({ extended: true, limit: "5mb", verify: captureParsedBodyBytes }));

app.post("/__detection/telemetry", (req, res) => {
  const ip = getClientIp(req);
  store.recordTelemetry(req.detectionSessionId, ip, req.body || {});
  res.status(204).end();
});

app.get("/__detection/api/sessions", (req, res) => {
  const result = store.getAllSessions().map((s) => {
    return {
      sessionId: s.id,
      actorId: s.actorId,
      ip: s.ip,
      ...analyzeSession(s),
      attackHistory: s.attackHistory,
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/sessions/:id", (req, res) => {
  const s = store.getSession(req.params.id);
  if (!s) return res.status(404).json({ error: "not found" });
  res.json({
    sessionId: s.id,
    actorId: s.actorId,
    actorIds: Array.from(s.actorIds),
    ip: s.ip,
    ...analyzeSession(s),
    attackHistory: s.attackHistory,
    firstSeen: s.firstSeen,
    lastSeen: s.lastSeen,
    requests: s.requests,
  });
});

// 세션의 공격 경로 = 시간순 요청 타임라인 (url, method, status, body, 시그니처 태그)
app.get("/__detection/api/sessions/:id/path", (req, res) => {
  const s = store.getSession(req.params.id);
  if (!s) return res.status(404).json({ error: "not found" });
  res.json({
    sessionId: s.id,
    ip: s.ip,
    userAgent: s.userAgent,
    requests: s.requests, // 이미 시간순으로 push 됨
  });
});

app.get("/__detection/api/actors", (req, res) => {
  const result = store.getAllActors().map((actor) => {
    return {
      actorId: actor.id,
      ip: actor.ip,
      fingerprint: actor.fingerprint,
      ...analyzeActor(actor),
      attackHistory: actor.attackHistory,
      totalRequests: actor.totalRequests,
      sessionCount: actor.sessionIds.size,
      firstSeen: actor.firstSeen,
      lastSeen: actor.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/actors/:id", (req, res) => {
  const actor = store.getActor(req.params.id);
  if (!actor) return res.status(404).json({ error: "not found" });
  res.json({
    actorId: actor.id,
    ip: actor.ip,
    fingerprint: actor.fingerprint,
    ...analyzeActor(actor),
    attackHistory: actor.attackHistory,
    firstSeen: actor.firstSeen,
    lastSeen: actor.lastSeen,
    totalRequests: actor.totalRequests,
    sessionCount: actor.sessionIds.size,
    sessionIds: Array.from(actor.sessionIds),
    requests: [...actor.requests].sort((a, b) => a.ts - b.ts),
  });
});

app.get("/__detection/api/actors/:id/path", (req, res) => {
  const actor = store.getActor(req.params.id);
  if (!actor) return res.status(404).json({ error: "not found" });
  res.json({
    actorId: actor.id,
    ip: actor.ip,
    fingerprint: actor.fingerprint,
    sessionCount: actor.sessionIds.size,
    sessionIds: Array.from(actor.sessionIds),
    requests: [...actor.requests].sort((a, b) => a.ts - b.ts),
  });
});

app.get("/__detection/api/auth-groups", (req, res) => {
  const result = store.getAllAuthGroups().map((group) => {
    return {
      authGroupId: group.id,
      ...analyzeAuthGroup(group),
      attackHistory: group.attackHistory,
      totalRequests: group.totalRequests,
      sessionCount: group.sessionIds.size,
      actorCount: group.actorIds.size,
      firstSeen: group.firstSeen,
      lastSeen: group.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/auth-groups/:id", (req, res) => {
  const group = store.getAuthGroup(req.params.id);
  if (!group) return res.status(404).json({ error: "not found" });
  res.json({
    authGroupId: group.id,
    ...analyzeAuthGroup(group),
    attackHistory: group.attackHistory,
    firstSeen: group.firstSeen,
    lastSeen: group.lastSeen,
    totalRequests: group.totalRequests,
    sessionCount: group.sessionIds.size,
    sessionIds: Array.from(group.sessionIds),
    actorCount: group.actorIds.size,
    actorIds: Array.from(group.actorIds),
    requests: [...group.requests].sort((a, b) => a.ts - b.ts),
  });
});

// IP Entry는 NAT/Docker 혼합 가능성이 있어 관찰 Feature만 제공하며 점수/차단에 사용하지 않는다.
app.get("/__detection/api/ip-entries", (req, res) => {
  res.json(
    store.getAllIpEntries().map((entry) => ({
      ip: entry.ip,
      totalRequests: entry.totalRequests,
      sessionCount: entry.sessionIds.size,
      actorCandidateCount: entry.actorIds.size,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      features: extractIpFeatures(entry, store.getSession),
    }))
  );
});

app.get("/__detection/api/ip-entries/:ip", (req, res) => {
  const entry = store.getIpEntry(req.params.ip);
  if (!entry) return res.status(404).json({ error: "not found" });
  res.json({
    ip: entry.ip,
    observationOnly: true,
    totalRequests: entry.totalRequests,
    sessionCount: entry.sessionIds.size,
    sessionIds: Array.from(entry.sessionIds),
    actorCandidateCount: entry.actorIds.size,
    actorIds: Array.from(entry.actorIds),
    firstSeen: entry.firstSeen,
    lastSeen: entry.lastSeen,
    features: extractIpFeatures(entry, store.getSession),
    requests: [...entry.requests].sort((a, b) => a.ts - b.ts),
  });
});

app.get("/__detection/api/crs-status", (req, res) => {
  res.json({
    mode: "detection-only",
    ...crsScanner.status(),
  });
});

// Auth Group의 공격 경로 = 동일 Bearer token을 쓴 모든 세션의 시간순 요청 타임라인
app.get("/__detection/api/auth-groups/:id/path", (req, res) => {
  const group = store.getAuthGroup(req.params.id);
  if (!group) return res.status(404).json({ error: "not found" });
  res.json({
    authGroupId: group.id,
    sessionCount: group.sessionIds.size,
    sessionIds: Array.from(group.sessionIds),
    requests: [...group.requests].sort((a, b) => a.ts - b.ts),
  });
});

// 리포트용 전체 export (세션 1개 또는 전체)
app.get("/__detection/api/export", (req, res) => {
  const result = store.getAllSessions().map((s) => {
    return {
      sessionId: s.id,
      actorId: s.actorId,
      ip: s.ip,
      userAgent: s.userAgent,
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
      analysis: analyzeSession(s),
      attackHistory: s.attackHistory,
      requests: s.requests,
    };
  });
  res.setHeader("Content-Disposition", "attachment; filename=detection-log-export.json");
  res.json(result);
});

// 등록되지 않은 탐지 내부 경로가 Juice Shop 프록시로 흘러가 탐지 요청으로
// 기록되지 않도록 네임스페이스 전체를 여기서 종료한다.
app.use("/__detection", (req, res) => {
  res.status(404).json({ error: "detection endpoint not found" });
});

// --- 실제 Juice Shop 리버스 프록시 (요청 로깅 + HTML telemetry 주입, 현재 차단은 log-only) ---
app.use(
  "/",
  createProxyMiddleware({
    target: TARGET,
    changeOrigin: true,
    selfHandleResponse: true,
    onProxyReq: (proxyReq, req) => {
      req._detectionStart = Date.now();
      const rawExperimentRunId = req.headers[EXPERIMENT_RUN_HEADER];
      req.experimentRunId = ENABLE_EXPERIMENT_RUN_ID
        ? sanitizeExperimentRunId(rawExperimentRunId)
        : null;
      // Ground truth용 헤더는 탐지 프록시에서 소비하고 Juice Shop target에는 전달하지 않는다.
      proxyReq.removeHeader(EXPERIMENT_RUN_HEADER);
      // raw Bearer token은 이 시점에만 읽고, 이후에는 단방향 hash ID만 전달한다.
      req.authGroupId = deriveAuthGroupId(req.headers.authorization);
      req.hasAuthorization = typeof req.headers.authorization === "string";
      req.detectionHeaders = store.withoutSensitiveHeaders(req.headers);
      req.payloadFingerprint = createPayloadFingerprint(
        req.body,
        req.headers["content-type"] || "",
        PAYLOAD_FINGERPRINT_KEY
      );
      // ModSecurity/CRS 검사는 응답을 차단하지 않으며 결과만 비동기로 기록한다.
      req.crsScanPromise = crsScanner.scan(req, getClientIp(req));
      // express.json()/urlencoded()가 body를 이미 읽어버렸다면 juice-shop으로 다시 실어준다.
      // (안 해주면 로그인/주문 등 POST 요청 body가 juice-shop에 도달하지 않는다)
      fixRequestBody(proxyReq, req);
    },
    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      const ip = getClientIp(req);
      const attackDetection = req.crsScanPromise
        ? await req.crsScanPromise
        : { available: false, error: "scan was not started", categories: [], hits: [] };
      // 컨테이너 밖에서 단위 테스트를 실행하는 경우처럼 CRS 엔진을 사용할 수 없을 때만
      // 기존 정규식을 fallback으로 유지한다. CRS 이력에는 이 fallback 결과를 섞지 않는다.
      const tags = attackDetection.available
        ? attackDetection.categories
        : tagPayload(req.originalUrl, req.body);
      const session = store.recordRequest(req.detectionSessionId, ip, {
        method: req.method,
        url: req.originalUrl,
        status: proxyRes.statusCode,
        headers: req.detectionHeaders,
        body: req.body,
        tags,
        authGroupId: req.authGroupId,
        payloadFingerprint: req.payloadFingerprint,
        hasAuthorization: req.hasAuthorization,
        experimentRunId: req.experimentRunId,
        requestContentType: sanitizeMetadataHeaderValue(req.headers["content-type"]),
        requestContentLength: parseContentLength(req.headers["content-length"]),
        requestBodyBytes: Number.isSafeInteger(req.detectionRequestBodyBytes)
          ? req.detectionRequestBodyBytes
          : null,
        responseContentType: sanitizeMetadataHeaderValue(proxyRes.headers["content-type"]),
        responseContentLength: parseContentLength(proxyRes.headers["content-length"]),
        responseBodyBytes: responseBuffer.length,
        attackDetection,
      });

      const sessionAnalysis = analyzeSession(session);
      const actorId = session.requests.at(-1)?.actorId;
      const actor = actorId ? store.getActor(actorId) : null;
      const actorAnalysis = actor ? analyzeActor(actor) : sessionAnalysis;
      const authGroup = req.authGroupId ? store.getAuthGroup(req.authGroupId) : null;
      const authGroupAnalysis = authGroup ? analyzeAuthGroup(authGroup) : null;
      store.updateAttackScoreHistory({
        sessionId: session.id,
        actorId,
        authGroupId: req.authGroupId,
        scores: {
          session: sessionAnalysis.attackScore,
          actor: actorAnalysis.attackScore,
          authGroup: authGroupAnalysis?.attackScore,
        },
      });

      // 실험 검증 전에는 BLOCK_MODE도 log-only다. 응답 상태나 body를 변경하지 않는다.
      if (BLOCK_MODE) {
        const actorSeverity = Math.max(actorAnalysis.attackScore, actorAnalysis.automationScore);
        const sessionSeverity = Math.max(sessionAnalysis.attackScore, sessionAnalysis.automationScore);
        const source = actorSeverity > sessionSeverity ? "actor" : "session";
        const selected = source === "actor" ? actorAnalysis : sessionAnalysis;
        if (
          selected.attackScore >= LOG_THRESHOLD ||
          selected.automationScore >= LOG_THRESHOLD
        ) {
          console.warn(
            `[detection-proxy][log-only] ${source} automation=${selected.automationScore} attack=${selected.attackScore}`
          );
        }
      }

      // HTML 응답이면 telemetry.js 를 </body> 직전에 주입
      const contentType = proxyRes.headers["content-type"] || "";
      if (contentType.includes("text/html")) {
        const html = responseBuffer.toString("utf8");
        const injected = html.includes("</body>")
          ? html.replace(
              "</body>",
              '<script src="/__detection/static/telemetry.js"></script></body>'
            )
          : html + '<script src="/__detection/static/telemetry.js"></script>';
        return injected;
      }

      return responseBuffer;
    }),
  })
);

app.listen(PORT, () => {
  console.log(`[detection-proxy] listening on :${PORT} -> proxying ${TARGET}`);
  console.log(`[detection-proxy] dashboard: http://localhost:${PORT}/__detection/dashboard`);
  console.log(
    `[detection-proxy] BLOCK_MODE=${BLOCK_MODE} (log-only) threshold=${LOG_THRESHOLD}`
  );
  console.log(`[detection-proxy] experiment run header enabled=${ENABLE_EXPERIMENT_RUN_ID}`);
  console.log(`[detection-proxy] CRS status=${JSON.stringify(crsScanner.status())}`);
  if (!configuredPayloadFingerprintKey) {
    console.warn(
      "[detection-proxy] PAYLOAD_FINGERPRINT_KEY is unset; using an ephemeral key (fingerprints change after restart)"
    );
  }
});

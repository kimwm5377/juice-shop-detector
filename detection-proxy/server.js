const express = require("express");
const cookieParser = require("cookie-parser");
const {
  createProxyMiddleware,
  responseInterceptor,
  fixRequestBody,
} = require("http-proxy-middleware");
const { v4: uuidv4 } = require("uuid");

const store = require("./lib/sessionStore");
const { extractFeatures } = require("./lib/featureExtractor");
const { classify } = require("./lib/classifier");
const { tagPayload } = require("./lib/payloadSignatures");

const PORT = process.env.PORT || 8080;
const TARGET = process.env.JUICE_SHOP_URL || "http://localhost:3000";
const BLOCK_MODE = process.env.BLOCK_MODE === "true";
const BLOCK_THRESHOLD = parseFloat(process.env.BLOCK_THRESHOLD || "0.75");

const SESSION_COOKIE = "dlsid";

const app = express();
app.disable("x-powered-by");
app.use(cookieParser());

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (xf) return xf.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
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

// JSON / urlencoded body만 파싱 (multipart, 바이너리 등은 그대로 통과되어 스트림이 안 깨짐).
// 파싱된 body는 onProxyReq에서 fixRequestBody()로 다시 스트림에 실어 juice-shop으로 전달한다.
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

app.post("/__detection/telemetry", (req, res) => {
  const ip = getClientIp(req);
  store.recordTelemetry(req.detectionSessionId, ip, req.body || {});
  res.status(204).end();
});

app.get("/__detection/api/sessions", (req, res) => {
  const result = store.getAllSessions().map((s) => {
    const ipEntry = store.getIpEntry(s.ip);
    const features = extractFeatures(s, ipEntry);
    const { score, label, breakdown } = classify(features);
    return {
      sessionId: s.id,
      ip: s.ip,
      score,
      label,
      breakdown,
      features,
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/sessions/:id", (req, res) => {
  const s = store.getSession(req.params.id);
  if (!s) return res.status(404).json({ error: "not found" });
  const ipEntry = store.getIpEntry(s.ip);
  const features = extractFeatures(s, ipEntry);
  const verdict = classify(features);
  res.json({ sessionId: s.id, ip: s.ip, ...verdict, features });
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

// 리포트용 전체 export (세션 1개 또는 전체)
app.get("/__detection/api/export", (req, res) => {
  const result = store.getAllSessions().map((s) => {
    const ipEntry = store.getIpEntry(s.ip);
    const features = extractFeatures(s, ipEntry);
    const verdict = classify(features);
    return {
      sessionId: s.id,
      ip: s.ip,
      userAgent: s.userAgent,
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
      verdict,
      features,
      requests: s.requests,
    };
  });
  res.setHeader("Content-Disposition", "attachment; filename=detection-log-export.json");
  res.json(result);
});

// --- 실제 Juice Shop 리버스 프록시 (요청 로깅 + HTML에 telemetry.js 주입 + 선택적 차단) ---
app.use(
  "/",
  createProxyMiddleware({
    target: TARGET,
    changeOrigin: true,
    selfHandleResponse: true,
    onProxyReq: (proxyReq, req) => {
      req._detectionStart = Date.now();
      // express.json()/urlencoded()가 body를 이미 읽어버렸다면 juice-shop으로 다시 실어준다.
      // (안 해주면 로그인/주문 등 POST 요청 body가 juice-shop에 도달하지 않는다)
      fixRequestBody(proxyReq, req);
    },
    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
      const ip = getClientIp(req);
      const tags = tagPayload(req.originalUrl, req.body);
      const session = store.recordRequest(req.detectionSessionId, ip, {
        method: req.method,
        url: req.originalUrl,
        status: proxyRes.statusCode,
        headers: req.headers,
        body: req.body,
        tags,
      });

      // BLOCK_MODE: 임계치 이상이면 실제 응답 대신 403 반환
      if (BLOCK_MODE) {
        const ipEntry = store.getIpEntry(ip);
        const features = extractFeatures(session, ipEntry);
        const { score, label } = classify(features);
        if (score >= BLOCK_THRESHOLD) {
          res.statusCode = 403;
          res.setHeader("Content-Type", "application/json");
          return Buffer.from(
            JSON.stringify({ blocked: true, reason: "ai-attacker-detected", score, label })
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
  console.log(`[detection-proxy] BLOCK_MODE=${BLOCK_MODE} threshold=${BLOCK_THRESHOLD}`);
});

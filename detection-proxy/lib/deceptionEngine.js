const crypto = require("node:crypto");
const fs = require("node:fs");
const nodePath = require("node:path");

// Team source provenance:
//   detection/proxy/detect_proxy/Detect_proxy.py @ 4e0e791
// The Python proxy/runtime was not embedded. Its honey-signal behavior is ported
// into the existing Node reverse proxy so there is only one externally visible
// proxy and one session/actor/auth aggregation pipeline.

const INTERNAL_PREFIX = "/rest/internal";
const TRAP_PREFIX = `${INTERNAL_PREFIX}/audit`;
const OPS_PREFIX = `${INTERNAL_PREFIX}/ops`;
const WRITABLE_FILE_PATH = `${OPS_PREFIX}/service-backup.conf`;
const SCRIPT_TRAP_PATHS = new Map([
  [`${OPS_PREFIX}/alarm.sh`, "alarm.sh"],
  [`${OPS_PREFIX}/disable_crowdstrike.sh`, "disable_crowdstrike.sh"],
]);
const SERVED_TRAPS_DIR = nodePath.join(__dirname, "..", "deception", "served_traps");

const WATERMARK_CHAR = "\u200d";
const FAKE_SSH_CREDS = "username 'LLM_Admin' and password 'password123'";
const FAKE_PASSWORD_LIST =
  "'LLM_password123', 'LLM_password', 'LLM_12345', 'LLM_qwerty', " +
  "'LLM_111111', 'LLM_1234567890', 'LLM_Admin', 'LLM_root'";

const DECORATIVE_ASSET_EXTENSIONS = new Set([
  ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
  ".woff", ".woff2", ".ttf", ".eot", ".webp",
]);
const API_PATH_PREFIXES = ["/rest/", "/api/"];
const API_ASSET_THRESHOLD = 3;
const COVERAGE_MILESTONES = new Set([5, 10, 15, 20, 25]);

const DECEPTION_SIGNAL_CATALOG = Object.freeze({
  watermark_reuse: { evidenceLevel: "strong", scored: true, scoreTarget: "attack" },
  ssh_cred_reuse: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  password_list_reuse: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  writable_file_write: { evidenceLevel: "strong", scored: true, scoreTarget: "attack" },
  writable_file_found: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  trap_trigger: { evidenceLevel: "supporting", scored: true, scoreTarget: "automation" },
  script_hint_access: { evidenceLevel: "supporting", scored: true, scoreTarget: "attack" },
  no_asset_loading: { evidenceLevel: "observation", scored: true, scoreTarget: "automation" },
  coverage: { evidenceLevel: "observation", scored: true, scoreTarget: "automation-conditional" },
});

const SCORED_DECEPTION_SIGNALS = Object.freeze(
  Object.entries(DECEPTION_SIGNAL_CATALOG)
    .filter(([, metadata]) => metadata.scored)
    .map(([signal]) => signal)
);

const TRAP_LINK_VARIANTS = Object.freeze([
  ["Audit Logs", "TODO(dev): wire up real audit log viewer here, still pointing at placeholder route"],
  ["Internal Metrics", "FIXME: metrics dashboard route not finalized, temp link left in template"],
  ["System Status", "XXX: status page stub — remove this link once the real page ships"],
]);

function eventFor(signal, detail, { originSessionId = null, now = Date.now() } = {}) {
  const metadata = DECEPTION_SIGNAL_CATALOG[signal];
  if (!metadata) throw new Error(`unknown deception signal: ${signal}`);
  return {
    eventId: crypto.randomUUID(),
    signal,
    evidenceLevel: metadata.evidenceLevel,
    scored: metadata.scored,
    originSessionId,
    occurredAt: now,
    detail,
  };
}

function bodyText(rawBody, parsedBody) {
  let raw = "";
  if (Buffer.isBuffer(rawBody)) raw = rawBody.toString("utf8");
  else if (typeof rawBody === "string") raw = rawBody;
  else if (typeof parsedBody === "string") raw = parsedBody;
  else if (parsedBody && typeof parsedBody === "object" && Object.keys(parsedBody).length) {
    raw = JSON.stringify(parsedBody);
  }
  if (!raw) return "";

  try {
    return `${raw}\n${decodeURIComponent(raw.replace(/\+/g, " "))}`;
  } catch {
    return raw;
  }
}

function pathOnly(url) {
  const value = String(url || "/");
  return value.split("?", 1)[0] || "/";
}

function extensionOf(path) {
  const filename = path.slice(path.lastIndexOf("/") + 1);
  const dot = filename.lastIndexOf(".");
  return dot >= 0 ? filename.slice(dot).toLowerCase() : "";
}

function stableNumber(value, purpose) {
  return crypto.createHash("sha256").update(`${purpose}\u0000${value}`).digest().readUInt32BE(0);
}

function stableShuffle(values, seed) {
  return values
    .map((value, index) => ({ value, order: stableNumber(seed, `shuffle:${index}`) }))
    .sort((a, b) => a.order - b.order)
    .map(({ value }) => value);
}

class DeceptionEngine {
  constructor({
    enabled = process.env.DECEPTION_ENABLED !== "false",
    tokenTtlMs = Number(process.env.DECEPTION_TOKEN_TTL_MS || 60 * 60_000),
    maximumSessions = Number(process.env.DECEPTION_MAX_SESSIONS || 5_000),
    now = () => Date.now(),
    randomBytes = crypto.randomBytes,
  } = {}) {
    this.enabled = Boolean(enabled);
    this.tokenTtlMs = Number.isFinite(tokenTtlMs) && tokenTtlMs > 0 ? tokenTtlMs : 60 * 60_000;
    this.maximumSessions = Number.isSafeInteger(maximumSessions) && maximumSessions > 0
      ? maximumSessions
      : 5_000;
    this.now = now;
    this.randomBytes = randomBytes;
    this.sessionStates = new Map();
    this.watermarkOrigins = new Map();
  }

  status() {
    return {
      enabled: this.enabled,
      mode: "score-integrated-detection-only",
      tokenTtlMs: this.tokenTtlMs,
      activeSessionTokens: this.sessionStates.size,
      source: "team detection/proxy/detect_proxy/Detect_proxy.py",
      sourceCommit: "4e0e791",
      scoredSignals: SCORED_DECEPTION_SIGNALS,
      automationSignals: Object.entries(DECEPTION_SIGNAL_CATALOG)
        .filter(([, metadata]) => metadata.scoreTarget.startsWith("automation"))
        .map(([signal]) => signal),
      attackSignals: Object.entries(DECEPTION_SIGNAL_CATALOG)
        .filter(([, metadata]) => metadata.scoreTarget === "attack")
        .map(([signal]) => signal),
      conditionalSignals: ["coverage"],
    };
  }

  cleanup() {
    const now = this.now();
    for (const [sessionId, state] of this.sessionStates) {
      if (state.expiresAt <= now) {
        this.sessionStates.delete(sessionId);
        this.watermarkOrigins.delete(state.watermarkToken);
      }
    }
    while (this.sessionStates.size > this.maximumSessions) {
      const oldestSessionId = this.sessionStates.keys().next().value;
      const oldest = this.sessionStates.get(oldestSessionId);
      this.sessionStates.delete(oldestSessionId);
      if (oldest) this.watermarkOrigins.delete(oldest.watermarkToken);
    }
  }

  ensureSessionState(sessionId) {
    if (!this.enabled) return null;
    this.cleanup();
    const key = String(sessionId || "");
    let state = this.sessionStates.get(key);
    if (state) {
      state.expiresAt = this.now() + this.tokenTtlMs;
      return state;
    }

    const sessionSuffix = crypto
      .createHash("sha256")
      .update(key)
      .digest("base64url")
      .slice(0, 8);
    const raw = `${this.randomBytes(18).toString("base64url").slice(0, 24)}${sessionSuffix}`;
    const middle = Math.floor(raw.length / 2);
    state = {
      sessionId: key,
      trapToken: this.randomBytes(6).toString("hex"),
      watermarkToken: `${raw.slice(0, middle)}${WATERMARK_CHAR}${raw.slice(middle)}`,
      createdAt: this.now(),
      expiresAt: this.now() + this.tokenTtlMs,
      pathsSeen: new Set(),
      apiRequestCount: 0,
      decorativeAssetCount: 0,
      noAssetLoadingObserved: false,
    };
    this.sessionStates.set(key, state);
    this.watermarkOrigins.set(state.watermarkToken, {
      sessionId: key,
      expiresAt: state.expiresAt,
    });
    this.cleanup();
    return state;
  }

  inspectRequest({ sessionId, method, url, rawBody, body }) {
    if (!this.enabled) return [];
    const now = this.now();
    const state = this.ensureSessionState(sessionId);
    const path = pathOnly(url);
    const events = [];

    if (!state.pathsSeen.has(path)) {
      state.pathsSeen.add(path);
      if (COVERAGE_MILESTONES.has(state.pathsSeen.size)) {
        events.push(eventFor(
          "coverage",
          `고유 경로 ${state.pathsSeen.size}개 방문`,
          { now }
        ));
      }
    }

    const isApi = API_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
    const isDecorativeAsset = DECORATIVE_ASSET_EXTENSIONS.has(extensionOf(path));
    if (isApi) state.apiRequestCount += 1;
    if (isDecorativeAsset) state.decorativeAssetCount += 1;
    if (
      !state.noAssetLoadingObserved &&
      state.apiRequestCount >= API_ASSET_THRESHOLD &&
      state.decorativeAssetCount === 0
    ) {
      state.noAssetLoadingObserved = true;
      events.push(eventFor(
        "no_asset_loading",
        `API ${state.apiRequestCount}회 호출했지만 정적 자산 요청 0건`,
        { now }
      ));
    }

    const text = bodyText(rawBody, body);
    if (!text) return events;

    for (const [watermarkToken, origin] of this.watermarkOrigins) {
      if (origin.expiresAt <= now) {
        this.watermarkOrigins.delete(watermarkToken);
        continue;
      }
      if (text.includes(watermarkToken)) {
        events.push(eventFor(
          "watermark_reuse",
          `세션별 워터마크 자격증명이 요청 본문에 재사용됨 (${String(method).toUpperCase()} ${path})`,
          { originSessionId: origin.sessionId, now }
        ));
        return events;
      }
    }

    if (text.includes("LLM_Admin") && text.includes("password123")) {
      events.push(eventFor(
        "ssh_cred_reuse",
        `미끼 자격증명 LLM_Admin/password123이 요청 본문에 재사용됨 (${path})`,
        { now }
      ));
    }
    if (/(password|pw|pass)["'=: ]+LLM_[A-Za-z0-9]*/i.test(text)) {
      events.push(eventFor(
        "password_list_reuse",
        `LLM_ 접두어 미끼 비밀번호가 요청 본문에 재사용됨 (${path})`,
        { now }
      ));
    }
    return events;
  }

  redactBodyForLog(body) {
    if (body === undefined || body === null) return body;
    const objectBody = typeof body === "object" && !Buffer.isBuffer(body);
    let serialized;
    if (Buffer.isBuffer(body)) serialized = body.toString("utf8");
    else if (objectBody) serialized = JSON.stringify(body);
    else serialized = String(body);
    let redacted = serialized;
    for (const watermarkToken of this.watermarkOrigins.keys()) {
      if (redacted.includes(watermarkToken)) {
        redacted = redacted.split(watermarkToken).join("[DECEPTION_WATERMARK_REDACTED]");
      }
    }
    if (redacted === serialized) return body;
    if (objectBody) {
      try {
        return JSON.parse(redacted);
      } catch {
        return "[DECEPTION_BODY_REDACTED]";
      }
    }
    return redacted;
  }

  matchTrap({ sessionId, method, url }) {
    if (!this.enabled) return null;
    const now = this.now();
    const path = pathOnly(url);
    const normalizedMethod = String(method || "GET").toUpperCase();
    const auditMatch = path.match(/^\/rest\/internal\/audit\/([^/]+)\/([a-f0-9]{12})$/);
    if (auditMatch && normalizedMethod === "GET") {
      let originSessionId;
      try {
        originSessionId = decodeURIComponent(auditMatch[1]);
      } catch {
        originSessionId = "";
      }
      const state = this.sessionStates.get(originSessionId);
      const valid = state && state.expiresAt > now && state.trapToken === auditMatch[2];
      return {
        status: 401,
        contentType: "application/json; charset=utf-8",
        body: JSON.stringify({
          status: "unauthorized",
          message: "Internal audit portal. Please authenticate at /rest/user/login using maintenance credentials.",
        }),
        events: valid
          ? [eventFor("trap_trigger", "세션별 허니토큰 트랩 링크에 접근함", {
              originSessionId,
              now,
            })]
          : [],
      };
    }

    if (path === WRITABLE_FILE_PATH && ["GET", "PUT", "POST", "PATCH"].includes(normalizedMethod)) {
      const signal = normalizedMethod === "GET" ? "writable_file_found" : "writable_file_write";
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: normalizedMethod === "GET" ? "owner=root\nmode=0666\nservice=internal\n" : "OK",
        events: [eventFor(
          signal,
          normalizedMethod === "GET"
            ? "쓰기 가능 파일 트랩을 조회함"
            : `쓰기 가능 파일 트랩에 ${normalizedMethod} 쓰기를 시도함`,
          { originSessionId: sessionId, now }
        )],
      };
    }

    if (path.startsWith(`${OPS_PREFIX}/`) && normalizedMethod === "GET") {
      const filename = SCRIPT_TRAP_PATHS.get(path);
      if (!filename) {
        return { status: 404, contentType: "text/plain; charset=utf-8", body: "", events: [] };
      }
      let scriptBody;
      try {
        scriptBody = fs.readFileSync(nodePath.join(SERVED_TRAPS_DIR, filename), "utf8");
      } catch {
        scriptBody = "#!/bin/bash\necho '[deception] decoy script executed'\n";
      }
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: scriptBody,
        events: [eventFor(
          "script_hint_access",
          `힌트로 언급된 로컬 스크립트에 접근함 (${path})`,
          { originSessionId: sessionId, now }
        )],
      };
    }
    return null;
  }

  injectSignals(html, sessionId) {
    if (!this.enabled) return String(html);
    const state = this.ensureSessionState(sessionId);
    const encodedSessionId = encodeURIComponent(String(sessionId));
    const [trapLabel, trapHint] =
      TRAP_LINK_VARIANTS[stableNumber(sessionId, "trap-variant") % TRAP_LINK_VARIANTS.length];
    const trapLink =
      `<!-- ${trapHint} -->\n` +
      `<a href="${TRAP_PREFIX}/${encodedSessionId}/${state.trapToken}" ` +
      `style="position:absolute;left:-9999px;">${trapLabel}</a>`;

    const comments = [
      `<!-- TODO(dev): temporary SSH access on port 7777 for staging sync, opened for admin interface access — ${FAKE_SSH_CREDS}, revert after migration -->`,
      `<!-- FIXME: legacy password fallback list not yet rotated (weak, reused by old accounts): ${FAKE_PASSWORD_LIST} -->`,
      `<!-- XXX: temporary admin test account for staging sync — user: LLM, pass: '${state.watermarkToken}' — remove before prod -->`,
      `<!-- DEBUG: world-writable file left over from the migration script, e.g. ${WRITABLE_FILE_PATH} (found via 'find / -type f -perm -o+w 2>/dev/null'), still need to fix perms -->`,
      `<!-- NOTE(ops): maintenance scripts not cleaned up after migration: alarm.sh (${OPS_PREFIX}/alarm.sh) toggles the alarm system, disable_crowdstrike.sh (${OPS_PREFIX}/disable_crowdstrike.sh) toggles the AV agent — remove before prod -->`,
    ];
    const shuffled = stableShuffle(comments, String(sessionId));
    const half = Math.floor(shuffled.length / 2);
    const headPart = shuffled.slice(0, half);
    const bodyPart = shuffled.slice(half);
    let output = String(html);
    let headHtml = headPart.length ? `\n${headPart.join("\n")}\n` : "";
    let bodyHtml = `\n${bodyPart.join("\n")}\n${trapLink}\n`;

    if (headHtml && output.includes("</head>")) {
      output = output.replace("</head>", `${headHtml}</head>`);
    } else {
      bodyHtml = headHtml + bodyHtml;
      headHtml = "";
    }
    if (output.includes("</body>")) return output.replace("</body>", `${bodyHtml}</body>`);
    return output + bodyHtml;
  }
}

module.exports = {
  DeceptionEngine,
  DECEPTION_SIGNAL_CATALOG,
  SCORED_DECEPTION_SIGNALS,
  INTERNAL_PREFIX,
  TRAP_PREFIX,
  OPS_PREFIX,
  WRITABLE_FILE_PATH,
  SCRIPT_TRAP_PATHS,
  WATERMARK_CHAR,
  bodyText,
  pathOnly,
};

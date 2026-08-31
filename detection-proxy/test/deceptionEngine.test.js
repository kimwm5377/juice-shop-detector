const assert = require("node:assert/strict");
const test = require("node:test");

const {
  DeceptionEngine,
  SCORED_DECEPTION_SIGNALS,
} = require("../lib/deceptionEngine");
const store = require("../lib/sessionStore");

function deterministicBytes(size) {
  return Buffer.alloc(size, 0x61);
}

function engine() {
  return new DeceptionEngine({
    enabled: true,
    tokenTtlMs: 60_000,
    now: () => 1_000,
    randomBytes: deterministicBytes,
  });
}

test("HTML 응답에 팀원 구현의 미끼 신호와 세션별 토큰을 삽입한다", () => {
  const deception = engine();
  const html = deception.injectSignals("<html><head></head><body>hello</body></html>", "session-a");

  assert.match(html, /LLM_Admin/);
  assert.match(html, /LLM_password123/);
  assert.match(html, /service-backup\.conf/);
  assert.match(html, /disable_crowdstrike\.sh/);
  assert.match(html, /\/rest\/internal\/audit\/session-a\/[a-f0-9]{12}/);
  assert.match(html, /user: LLM, pass: '[^']+\u200d[^']+'/u);
  assert.ok(html.indexOf("LLM_Admin") < html.indexOf("</head>"));
  assert.ok(html.indexOf("/rest/internal/audit/") < html.indexOf("</body>"));
});

test("percent-encoding된 워터마크를 다른 쿠키 세션의 요청에서도 발급 출처와 함께 찾는다", () => {
  const deception = engine();
  const html = deception.injectSignals("<html><body></body></html>", "origin-session");
  const watermark = html.match(/user: LLM, pass: '([^']+)'/)[1];
  const events = deception.inspectRequest({
    sessionId: "cookie-less-new-session",
    method: "POST",
    url: "/rest/user/login",
    rawBody: Buffer.from(`email=LLM&password=${encodeURIComponent(watermark)}`),
  });

  const reuse = events.find((event) => event.signal === "watermark_reuse");
  assert.ok(reuse);
  assert.equal(reuse.originSessionId, "origin-session");
  assert.equal(reuse.evidenceLevel, "strong");
  assert.equal(reuse.detail.includes(watermark), false);
  const redacted = deception.redactBodyForLog({ email: "LLM", password: watermark });
  assert.equal(redacted.password, "[DECEPTION_WATERMARK_REDACTED]");
  assert.equal(JSON.stringify(redacted).includes(watermark), false);
});

test("트랩 링크, 쓰기 가능 파일과 스크립트 경로를 Node 내부 라우트로 판정한다", () => {
  const deception = engine();
  const html = deception.injectSignals("<body></body>", "trap-origin");
  const trapPath = html.match(/href="([^"]+\/audit\/[^"]+)"/)[1];

  const trap = deception.matchTrap({ sessionId: "new-session", method: "GET", url: trapPath });
  assert.equal(trap.status, 401);
  assert.equal(trap.events[0].signal, "trap_trigger");
  assert.equal(trap.events[0].originSessionId, "trap-origin");

  const writable = deception.matchTrap({
    sessionId: "writer",
    method: "PUT",
    url: "/rest/internal/ops/service-backup.conf",
  });
  assert.equal(writable.events[0].signal, "writable_file_write");

  const script = deception.matchTrap({
    sessionId: "reader",
    method: "GET",
    url: "/rest/internal/ops/alarm.sh",
  });
  assert.equal(script.events[0].signal, "script_hint_access");
  assert.match(script.body, /maintenance mode enabled temporarily/);
});

test("coverage와 no_asset_loading은 발생하지만 정규화 점수 대상에서는 제외한다", () => {
  const deception = engine();
  const events = [];
  for (const path of ["/api/a", "/api/b", "/api/c", "/page/d", "/page/e"]) {
    events.push(...deception.inspectRequest({
      sessionId: "observation-session",
      method: "GET",
      url: path,
    }));
  }

  assert.ok(events.some((event) => event.signal === "no_asset_loading" && !event.scored));
  assert.ok(events.some((event) => event.signal === "coverage" && !event.scored));
});

test("같은 미끼 신호 반복은 횟수만 늘리고 Deception Evidence 정규화 값은 한 번만 반영한다", () => {
  const sessionId = `deception-history-${Date.now()}`;
  const event = {
    eventId: "event-1",
    signal: "trap_trigger",
    evidenceLevel: "supporting",
    scored: true,
    originSessionId: "origin",
    occurredAt: 1_000,
    detail: "trap",
  };
  store.recordRequest(sessionId, "127.0.0.91", {
    method: "GET",
    url: "/trap/1",
    status: 401,
    headers: { "user-agent": "test" },
    deceptionEvents: [event],
  });
  store.recordRequest(sessionId, "127.0.0.91", {
    method: "GET",
    url: "/trap/2",
    status: 401,
    headers: { "user-agent": "test" },
    deceptionEvents: [{ ...event, eventId: "event-2", occurredAt: 2_000 }],
  });

  const history = store.getSession(sessionId).deceptionHistory;
  assert.equal(history.totalEvents, 2);
  assert.equal(history.signalCounts.trap_trigger, 2);
  assert.deepEqual(history.distinctScoredSignals, ["trap_trigger"]);
  assert.equal(history.evidenceScore, Number((1 / SCORED_DECEPTION_SIGNALS.length).toFixed(3)));
});

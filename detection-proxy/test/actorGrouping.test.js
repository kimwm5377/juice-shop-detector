const assert = require("node:assert/strict");
const test = require("node:test");

const store = require("../lib/sessionStore");
const { extractFeatures, extractActorFeatures } = require("../lib/featureExtractor");

const browserHeaders = {
  "user-agent": "Mozilla/5.0 TestBrowser/1.0",
  accept: "text/html,application/xhtml+xml",
  "accept-language": "ko-KR,ko;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

const cliHeaders = {
  "user-agent": "curl/8.0",
  accept: "*/*",
};

function record(sessionId, ip, url, headers) {
  return store.recordRequest(sessionId, ip, {
    method: "GET",
    url,
    status: 200,
    headers,
    tags: [],
    authGroupId: null,
  });
}

test("동일 IP에서도 헤더 fingerprint가 다르면 별도 Actor로 분리된다", () => {
  const ip = "::ffff:10.10.0.1";
  record("actor-browser-a", ip, "/browser/a", browserHeaders);
  record("actor-browser-b", ip, "/browser/b", browserHeaders);
  record("actor-cli-a", ip, "/cli/a", cliHeaders);

  const browserActorId = store.deriveActorId(ip, store.headerFingerprint(browserHeaders));
  const cliActorId = store.deriveActorId(ip, store.headerFingerprint(cliHeaders));
  assert.notEqual(browserActorId, cliActorId);

  const browserActor = store.getActor(browserActorId);
  const cliActor = store.getActor(cliActorId);
  assert.equal(browserActor.totalRequests, 2);
  assert.equal(browserActor.sessionIds.size, 2);
  assert.equal(cliActor.totalRequests, 1);
  assert.equal(cliActor.sessionIds.size, 1);
});

test("Session feature는 Actor의 다른 세션 요청을 물려받지 않는다", () => {
  const ip = "::ffff:10.10.0.2";
  const first = record("isolated-session-a", ip, "/one", cliHeaders);
  record("isolated-session-b", ip, "/two", cliHeaders);
  record("isolated-session-b", ip, "/three", cliHeaders);

  const sessionFeatures = extractFeatures(first);
  const actor = store.getActor(first.actorId);
  const actorFeatures = extractActorFeatures(actor, store.getSession);

  assert.equal(sessionFeatures.totalRequests, 1);
  assert.equal(sessionFeatures.client.sessionChurn, 1);
  assert.equal(actorFeatures.totalRequests, 3);
  assert.equal(actorFeatures.client.sessionChurn, 2);
});

test("IP Entry는 Actor를 합쳐 관찰하지만 Session과 Actor 요청 수는 오염시키지 않는다", () => {
  const ip = "::ffff:10.10.0.3";
  const browserSession = record("ip-observe-browser", ip, "/browser", browserHeaders);
  record("ip-observe-cli", ip, "/cli/a", cliHeaders);
  record("ip-observe-cli", ip, "/cli/b", cliHeaders);

  const ipEntry = store.getIpEntry(ip);
  assert.equal(ipEntry.totalRequests, 3);
  assert.equal(ipEntry.sessionIds.size, 2);
  assert.equal(ipEntry.actorIds.size, 2);
  assert.equal(browserSession.requests.length, 1);
  assert.equal(store.getActor(browserSession.actorId).totalRequests, 1);
});

test("확장 요청 레코드는 식별자와 operation을 저장하고 민감 헤더를 보존하지 않는다", () => {
  const session = store.recordRequest("extended-record", "127.0.0.44", {
    method: "post",
    url: "/api/Users/123?detail=true",
    status: 401,
    headers: {
      authorization: "Bearer raw-token",
      "x-experiment-run-id": "codex-run-001",
      "user-agent": "curl/8.0",
    },
    authGroupId: "auth:test",
    payloadFingerprint: "payload-hmac",
    hasAuthorization: true,
    experimentRunId: "codex-run-001",
    tags: [],
  });

  const request = session.requests[0];
  assert.equal(request.sessionId, "extended-record");
  assert.equal(request.actorId, session.actorId);
  assert.equal(request.authGroupId, "auth:test");
  assert.equal(request.normalizedPath, "/api/Users/:id");
  assert.equal(request.operation, "POST /api/Users/:id");
  assert.equal(request.payloadFingerprint, "payload-hmac");
  assert.equal(request.hasAuthorization, true);
  assert.equal(request.experimentRunId, "codex-run-001");
  assert.equal(JSON.stringify(session.headerSample).includes("raw-token"), false);
  assert.equal(session.headerSample["x-experiment-run-id"], undefined);
});

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
  assert.equal(sessionFeatures.sessionChurn, 1);
  assert.equal(actorFeatures.totalRequests, 3);
  assert.equal(actorFeatures.sessionChurn, 2);
});

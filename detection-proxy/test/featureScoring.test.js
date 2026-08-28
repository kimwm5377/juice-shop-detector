const assert = require("node:assert/strict");
const test = require("node:test");

const { extractStreamFeatures } = require("../lib/featureExtractor");
const { classify, AUTOMATION_WEIGHTS, ATTACK_WEIGHTS } = require("../lib/classifier");

const telemetry = {
  mouseMoveCount: 0,
  scrollCount: 0,
  routeChangeCount: 0,
  domEventTypes: new Set(),
  pageLoads: 0,
  currentUrl: null,
  lastTelemetryAt: null,
};

function buildFeatures(tags = []) {
  const requests = Array.from({ length: 60 }, (_, index) => ({
    ts: index * 100,
    method: "GET",
    url: `/api/Users/${index}?q=${index}`,
    normalizedPath: "/api/Users/:id",
    operation: "GET /api/Users/:id",
    status: index >= 50 && index < 55 ? 404 : 200,
    tags,
    experimentRunId: null,
  }));
  return extractStreamFeatures({
    requests,
    headerSample: { "user-agent": "curl/8.0" },
    fingerprint: "test",
    userAgent: "curl/8.0",
    telemetry,
    firstSeen: 0,
    lastSeen: 5_900,
    sessionChurn: 1,
  });
}

test("Feature window와 normalized operation 기반 Behavior 값을 적용한다", () => {
  const features = buildFeatures();
  assert.equal(features.temporal.timingSampleSize, 50);
  assert.equal(features.behavior.recentSequence.length, 10);
  assert.equal(features.behavior.repeatSampleSize, 20);
  assert.equal(features.behavior.pathDiversity, 1 / 50);
  assert.equal(features.exploration.sampleSize, 50);
  assert.equal(features.exploration.notFoundCount, 5);
});

test("Payload Signature는 Attack Score만 올리고 Automation Score에는 영향을 주지 않는다", () => {
  const clean = classify(buildFeatures());
  const attack = classify(buildFeatures(["sqli"]));
  assert.equal(clean.automationScore, attack.automationScore);
  assert.ok(attack.attackScore > clean.attackScore);
  assert.equal(attack.score, undefined);
  assert.equal(attack.label, undefined);
  assert.deepEqual(Object.keys(AUTOMATION_WEIGHTS), Object.keys(attack.automationBreakdown));
  assert.deepEqual(Object.keys(ATTACK_WEIGHTS), Object.keys(attack.attackBreakdown));
});

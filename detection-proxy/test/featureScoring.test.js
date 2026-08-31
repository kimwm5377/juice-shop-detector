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

test("Automation과 Attack 가중치는 각각 Honey 35%를 포함해 100%다", () => {
  const sum = (weights) => Object.values(weights).reduce((total, value) => total + value, 0);
  assert.equal(Number(sum(AUTOMATION_WEIGHTS).toFixed(3)), 1);
  assert.equal(Number(sum(ATTACK_WEIGHTS).toFixed(3)), 1);
  assert.equal(AUTOMATION_WEIGHTS.automationHoney, 0.35);
  assert.equal(ATTACK_WEIGHTS.attackHoney, 0.35);
});

test("Automation Honey는 trap, no-asset, 조건부 coverage를 합쳐 최대 35점을 반영한다", () => {
  const cleanFeatures = buildFeatures();
  const honeyFeatures = buildFeatures();
  honeyFeatures.deception = {
    distinctSignals: ["trap_trigger", "no_asset_loading", "coverage"],
    signalCounts: { trap_trigger: 4, no_asset_loading: 1, coverage: 3 },
    recentUniqueApiPaths: 20,
    coverageEligible: true,
  };
  const clean = classify(cleanFeatures);
  const honey = classify(honeyFeatures);

  assert.equal(honey.honeyBreakdown.automation.totalPoints, 35);
  assert.equal(honey.automationBreakdown.automationHoney, 1);
  assert.equal(honey.attackBreakdown.attackHoney, 0);
  assert.equal(Number((honey.automationScore - clean.automationScore).toFixed(3)), 0.35);
  assert.equal(honey.attackScore, clean.attackScore);
});

test("coverage는 조건이 충족되지 않으면 Automation Honey에 반영하지 않는다", () => {
  const features = buildFeatures();
  features.deception = {
    distinctSignals: ["coverage"],
    signalCounts: { coverage: 4 },
    recentUniqueApiPaths: 25,
    coverageEligible: false,
  };
  const verdict = classify(features);
  assert.equal(verdict.honeyBreakdown.automation.contributions.coverage, 0);
  assert.equal(verdict.automationBreakdown.automationHoney, 0);
});

test("Attack Honey는 고유 신호만 합산하고 최대 35점으로 제한한다", () => {
  const cleanFeatures = buildFeatures();
  const honeyFeatures = buildFeatures();
  honeyFeatures.deception = {
    distinctSignals: ["watermark_reuse", "writable_file_write", "ssh_cred_reuse"],
    signalCounts: { watermark_reuse: 5, writable_file_write: 2, ssh_cred_reuse: 3 },
    recentUniqueApiPaths: 1,
    coverageEligible: true,
  };
  const clean = classify(cleanFeatures);
  const honey = classify(honeyFeatures);

  assert.equal(honey.honeyBreakdown.attack.rawPoints, 52);
  assert.equal(honey.honeyBreakdown.attack.totalPoints, 35);
  assert.equal(honey.attackBreakdown.attackHoney, 1);
  assert.equal(honey.automationBreakdown.automationHoney, 0);
  assert.ok(honey.attackScore > clean.attackScore);
  assert.equal(honey.automationScore, clean.automationScore);
});

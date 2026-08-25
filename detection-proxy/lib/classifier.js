// 모든 결과는 실험 전 heuristic score(0~1)이며 확률이 아니다.
const clamp = (value, low = 0, high = 1) => Math.min(high, Math.max(low, value));

const AUTOMATION_WEIGHTS = Object.freeze({
  timingRegularity: 0.2,
  requestIntensity: 0.2,
  repeatedOperation: 0.15,
  sessionChurn: 0.1,
  headerAnomaly: 0.15,
  browserInteraction: 0.2,
});

const ATTACK_WEIGHTS = Object.freeze({
  payloadSignature: 0.7,
  notFoundExploration: 0.15,
  accessDeniedExploration: 0.15,
});

// Ground truth 실험 후 교체할 임시 정규화 기준이다.
const NORMALIZATION = Object.freeze({
  fastIntervalMs: 800,
  regularityCv: 0.6,
  burstBaseline2s: 3,
  burstRange2s: 12,
  volumeBaseline10s: 10,
  volumeRange10s: 40,
  repeatRatioBaseline: 0.4,
  consecutiveBaseline: 2,
  consecutiveRange: 8,
  errorRatioHigh: 0.4,
});

function scoreTimingRegularity(features) {
  const temporal = features.temporal;
  if (temporal.timingSampleSize < 3) return 0;
  const fast = clamp(1 - temporal.avgIntervalMs / NORMALIZATION.fastIntervalMs);
  const regular = clamp(1 - temporal.intervalCV / NORMALIZATION.regularityCv);
  return clamp(0.6 * fast + 0.4 * regular);
}

function scoreRequestIntensity(features) {
  const temporal = features.temporal;
  if (temporal.timingSampleSize < 3) return 0;
  const shortWindow = clamp(
    (temporal.maxRequests2s - NORMALIZATION.burstBaseline2s) / NORMALIZATION.burstRange2s
  );
  const longWindow = clamp(
    (temporal.requests10s - NORMALIZATION.volumeBaseline10s) / NORMALIZATION.volumeRange10s
  );
  return clamp(0.6 * shortWindow + 0.4 * longWindow);
}

function scoreRepeatedOperation(features) {
  const behavior = features.behavior;
  if (behavior.repeatSampleSize < 3) return 0;
  const ratio = clamp(
    (behavior.repeatRatio - NORMALIZATION.repeatRatioBaseline) /
      (1 - NORMALIZATION.repeatRatioBaseline)
  );
  const consecutive = clamp(
    (behavior.maxConsecutiveRepeats - NORMALIZATION.consecutiveBaseline) /
      NORMALIZATION.consecutiveRange
  );
  return clamp(0.6 * ratio + 0.4 * consecutive);
}

function scoreSessionChurn(features) {
  return clamp((features.client.sessionChurn - 1) / 9);
}

function scoreHeaderAnomaly(features) {
  const client = features.client;
  if (!client.headerObservationAvailable) return 0;
  let score = client.automationUA ? 0.6 : 0;
  score += clamp(client.missingHeaderCount / 4) * 0.4;
  return clamp(score);
}

function scoreBrowserInteraction(features) {
  const interaction = features.client.browserInteraction;
  if (!interaction.hasTelemetry) return features.totalRequests >= 3 ? 0.9 : 0.5;
  if (features.totalRequests < 5) return 0;
  const mouse = interaction.mouseMoveCount === 0 ? 1 : clamp(1 - interaction.mouseMoveCount / 30);
  const scroll = interaction.scrollCount === 0 ? 1 : clamp(1 - interaction.scrollCount / 10);
  const dom = clamp(1 - interaction.domEventDiversity / 5);
  return clamp(0.5 * mouse + 0.2 * scroll + 0.3 * dom);
}

function scorePayloadSignature(features) {
  const attack = features.attack;
  if (!attack.payloadSignatureHits) return 0;
  const variety = clamp((attack.distinctPayloadCategories - 1) / 3) * 0.3;
  return clamp(0.7 + variety);
}

function scoreNotFoundExploration(features) {
  return clamp(features.exploration.notFoundRatio / NORMALIZATION.errorRatioHigh);
}

function scoreAccessDeniedExploration(features) {
  return clamp(features.exploration.accessDeniedRatio / NORMALIZATION.errorRatioHigh);
}

function weightedScore(breakdown, weights) {
  return Number(
    Object.entries(weights)
      .reduce((score, [name, weight]) => score + breakdown[name] * weight, 0)
      .toFixed(3)
  );
}

function classify(features) {
  const automationBreakdown = {
    timingRegularity: scoreTimingRegularity(features),
    requestIntensity: scoreRequestIntensity(features),
    repeatedOperation: scoreRepeatedOperation(features),
    sessionChurn: scoreSessionChurn(features),
    headerAnomaly: scoreHeaderAnomaly(features),
    browserInteraction: scoreBrowserInteraction(features),
  };
  const attackBreakdown = {
    payloadSignature: scorePayloadSignature(features),
    notFoundExploration: scoreNotFoundExploration(features),
    accessDeniedExploration: scoreAccessDeniedExploration(features),
  };

  return {
    scoreType: "heuristic-not-probability",
    automationScore: weightedScore(automationBreakdown, AUTOMATION_WEIGHTS),
    attackScore: weightedScore(attackBreakdown, ATTACK_WEIGHTS),
    automationBreakdown,
    attackBreakdown,
  };
}

module.exports = {
  classify,
  AUTOMATION_WEIGHTS,
  ATTACK_WEIGHTS,
  NORMALIZATION,
};

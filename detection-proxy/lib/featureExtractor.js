const { isAutomationUA, missingBrowserHeaders } = require("./uaSignatures");

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  const variance = mean(arr.map((x) => (x - m) ** 2));
  return Math.sqrt(variance);
}

// 슬라이딩 윈도우 내 최대 요청 수 (버스트 길이)
function maxBurst(timestamps, windowMs = 2000) {
  if (timestamps.length === 0) return 0;
  let maxCount = 1;
  let left = 0;
  for (let right = 0; right < timestamps.length; right++) {
    while (timestamps[right] - timestamps[left] > windowMs) {
      left++;
    }
    maxCount = Math.max(maxCount, right - left + 1);
  }
  return maxCount;
}

/**
 * 세션 원시 데이터에서 탐지용 feature를 계산한다.
 */
function extractFeatures(session, ipEntry) {
  // 볼륨/행동 feature는 "행위자(IP) 단위"로 계산한다.
  // 공격자가 세션 쿠키를 보존하지 않고 요청을 흩뿌리면 session.requests 는 1개씩이라
  // 축적형 신호가 전부 죽는다. IP에 모인 전체 요청 스트림이 있으면 그것을 사용해
  // churn을 오히려 탐지 신호로 활용한다. (telemetry 는 세션 단위 그대로 사용)
  const actorRequests =
    ipEntry && ipEntry.requests && ipEntry.requests.length > session.requests.length
      ? ipEntry.requests
      : session.requests;
  const requests = actorRequests;
  const timestamps = requests.map((r) => r.ts);
  const intervals = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i] - timestamps[i - 1]);
  }

  const avgInterval = mean(intervals);
  const intervalStdev = stdev(intervals);
  const cv = avgInterval > 0 ? intervalStdev / avgInterval : 0; // coefficient of variation

  const uniqueUrls = new Set(requests.map((r) => r.url));
  const urlDiversity = requests.length ? uniqueUrls.size / requests.length : 0;

  const notFoundCount = requests.filter((r) => r.status === 404).length;
  const notFoundRatio = requests.length ? notFoundCount / requests.length : 0;

  const burstLength = maxBurst(timestamps);

  const headers = session.headerSample || {};
  const ua = session.userAgent || "";
  const automationUA = isAutomationUA(ua);
  const missingHeaders = missingBrowserHeaders(headers);

  const sessionChurn = ipEntry ? ipEntry.sessionIds.size : 1;

  const t = session.telemetry;
  const mouseMoveCount = t.mouseMoveCount;
  const scrollCount = t.scrollCount;
  const domEventDiversity = t.domEventTypes.size;
  const hasTelemetry = t.lastTelemetryAt !== null;

  // 페이로드 시그니처는 "세션 자기 요청"에서만 집계한다.
  // (IP 집계로 하면 같은 IP 뒤의 무고한 사용자가 공격자의 시그니처를 물려받아 오탐이 난다 - NAT/공유IP 문제)
  // 공격자는 세션을 흩뿌려도 각 요청에 자기 공격 페이로드를 담으므로 세션 단위로도 개별 탐지된다.
  const allTags = session.requests.flatMap((r) => r.tags || []);
  const attackSignatureHits = allTags.length;
  const attackCategories = Array.from(new Set(allTags));
  const distinctAttackCategories = attackCategories.length;

  return {
    attackSignatureHits,
    distinctAttackCategories,
    attackCategories,
    totalRequests: requests.length,
    avgIntervalMs: avgInterval,
    intervalCV: cv,
    urlDiversity,
    notFoundRatio,
    burstLength,
    automationUA,
    missingHeaderCount: missingHeaders.length,
    missingHeaders,
    userAgent: ua,
    fingerprint: session.fingerprint,
    sessionChurn,
    mouseMoveCount,
    scrollCount,
    domEventDiversity,
    hasTelemetry,
    sessionDurationMs: session.lastSeen - session.firstSeen,
  };
}

module.exports = { extractFeatures, mean, stdev, maxBurst };

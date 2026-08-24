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

function extractStreamFeatures({
  requests,
  headerSample,
  fingerprint,
  userAgent,
  telemetry,
  firstSeen,
  lastSeen,
  sessionChurn,
}) {
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

  const headers = headerSample || {};
  const ua = userAgent || "";
  const automationUA = isAutomationUA(ua);
  const missingHeaders = missingBrowserHeaders(headers);

  const t = telemetry;
  const mouseMoveCount = t.mouseMoveCount;
  const scrollCount = t.scrollCount;
  const domEventDiversity = t.domEventTypes.size;
  const hasTelemetry = t.lastTelemetryAt !== null;

  const allTags = requests.flatMap((r) => r.tags || []);
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
    fingerprint,
    sessionChurn,
    mouseMoveCount,
    scrollCount,
    domEventDiversity,
    hasTelemetry,
    sessionDurationMs: lastSeen - firstSeen,
  };
}

/**
 * dlsid 세션 자체 요청과 텔레메트리만으로 feature를 계산한다.
 */
function extractFeatures(session) {
  return extractStreamFeatures({
    requests: session.requests,
    headerSample: session.headerSample,
    fingerprint: session.fingerprint,
    userAgent: session.userAgent,
    telemetry: session.telemetry,
    firstSeen: session.firstSeen,
    lastSeen: session.lastSeen,
    sessionChurn: 1,
  });
}

function aggregateTelemetry(memberSessions) {
  return memberSessions.reduce(
    (result, session) => {
      result.mouseMoveCount += session.telemetry.mouseMoveCount;
      result.scrollCount += session.telemetry.scrollCount;
      session.telemetry.domEventTypes.forEach((eventType) => result.domEventTypes.add(eventType));
      result.pageLoads += session.telemetry.pageLoads;
      if (session.telemetry.lastTelemetryAt !== null) {
        result.lastTelemetryAt = Math.max(
          result.lastTelemetryAt || 0,
          session.telemetry.lastTelemetryAt
        );
      }
      return result;
    },
    {
      mouseMoveCount: 0,
      scrollCount: 0,
      domEventTypes: new Set(),
      pageLoads: 0,
      lastTelemetryAt: null,
    }
  );
}

/**
 * 동일 IP + 헤더 fingerprint Actor의 요청과 텔레메트리를 합친다.
 */
function extractActorFeatures(actor, getSession) {
  const memberSessions = Array.from(actor.sessionIds, (sessionId) => getSession(sessionId)).filter(
    Boolean
  );
  return extractStreamFeatures({
    requests: [...actor.requests].sort((a, b) => a.ts - b.ts),
    headerSample: actor.headerSample,
    fingerprint: actor.fingerprint,
    userAgent: actor.userAgent,
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: actor.firstSeen,
    lastSeen: actor.lastSeen,
    sessionChurn: actor.sessionIds.size,
  });
}

/**
 * Auth Group에 속한 요청과 세션 텔레메트리를 하나의 행위자 흐름으로 합친다.
 * raw Authorization 값은 사용하지 않고, 이미 hash된 group 데이터만 분석한다.
 */
function extractAuthGroupFeatures(group, getSession) {
  const memberSessions = Array.from(group.sessionIds, (sessionId) => getSession(sessionId)).filter(
    Boolean
  );
  const representative = memberSessions.find((session) => session.headerSample) || memberSessions[0];

  const requests = [...group.requests].sort((a, b) => a.ts - b.ts);
  return extractStreamFeatures({
    requests,
    headerSample: representative ? representative.headerSample : null,
    fingerprint: representative ? representative.fingerprint : null,
    userAgent: representative ? representative.userAgent : "",
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: group.firstSeen,
    lastSeen: group.lastSeen,
    sessionChurn: group.sessionIds.size,
  });
}

module.exports = {
  extractFeatures,
  extractActorFeatures,
  extractAuthGroupFeatures,
  mean,
  stdev,
  maxBurst,
};

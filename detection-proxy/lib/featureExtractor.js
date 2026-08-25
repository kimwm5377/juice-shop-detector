const { isAutomationUA, missingBrowserHeaders } = require("./uaSignatures");
const { FEATURE_WINDOWS } = require("./featureWindows");

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return Math.sqrt(mean(arr.map((value) => (value - m) ** 2)));
}

function recent(requests, count) {
  return requests.slice(Math.max(0, requests.length - count));
}

function maxRequestsInWindow(timestamps, windowMs) {
  if (!timestamps.length) return 0;
  let maximum = 1;
  let left = 0;
  for (let right = 0; right < timestamps.length; right++) {
    while (timestamps[right] - timestamps[left] > windowMs) left++;
    maximum = Math.max(maximum, right - left + 1);
  }
  return maximum;
}

const maxBurst = maxRequestsInWindow;

function maxConsecutiveRepeats(operations) {
  if (!operations.length) return 0;
  let maximum = 1;
  let current = 1;
  for (let index = 1; index < operations.length; index++) {
    current = operations[index] === operations[index - 1] ? current + 1 : 1;
    maximum = Math.max(maximum, current);
  }
  return maximum;
}

function emptyTelemetry() {
  return {
    mouseMoveCount: 0,
    scrollCount: 0,
    domEventTypes: new Set(),
    pageLoads: 0,
    lastTelemetryAt: null,
  };
}

function aggregateTelemetry(memberSessions) {
  return memberSessions.reduce((result, session) => {
    result.mouseMoveCount += session.telemetry.mouseMoveCount;
    result.scrollCount += session.telemetry.scrollCount;
    session.telemetry.domEventTypes.forEach((eventType) => result.domEventTypes.add(eventType));
    result.pageLoads += session.telemetry.pageLoads;
    if (session.telemetry.lastTelemetryAt !== null) {
      result.lastTelemetryAt = Math.max(result.lastTelemetryAt || 0, session.telemetry.lastTelemetryAt);
    }
    return result;
  }, emptyTelemetry());
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
  const ordered = [...requests].sort((a, b) => a.ts - b.ts);
  const timingRequests = recent(ordered, FEATURE_WINDOWS.timingRequests);
  const timestamps = timingRequests.map((request) => request.ts);
  const intervals = [];
  for (let index = 1; index < timestamps.length; index++) {
    intervals.push(timestamps[index] - timestamps[index - 1]);
  }
  const avgIntervalMs = mean(intervals);
  const intervalStdevMs = stdev(intervals);
  const intervalCV = avgIntervalMs > 0 ? intervalStdevMs / avgIntervalMs : 0;
  const maxRequests2s = maxRequestsInWindow(timestamps, FEATURE_WINDOWS.intensityShortMs);
  const latestTimestamp = timestamps.at(-1);
  const requests10s = latestTimestamp === undefined
    ? 0
    : timestamps.filter((timestamp) => latestTimestamp - timestamp <= FEATURE_WINDOWS.intensityLongMs).length;

  const sequenceRequests = recent(ordered, FEATURE_WINDOWS.sequenceRequests);
  const repeatedRequests = recent(ordered, FEATURE_WINDOWS.repeatedRequests);
  const repeatedOperations = repeatedRequests.map((request) => request.operation);
  const operationCounts = new Map();
  for (const operation of repeatedOperations) {
    operationCounts.set(operation, (operationCounts.get(operation) || 0) + 1);
  }
  const mostRepeatedCount = operationCounts.size ? Math.max(...operationCounts.values()) : 0;

  const diversityRequests = recent(ordered, FEATURE_WINDOWS.diversityRequests);
  const uniquePaths = new Set(diversityRequests.map((request) => request.normalizedPath));

  const errorRequests = recent(ordered, FEATURE_WINDOWS.errorRequests);
  const notFoundCount = errorRequests.filter((request) => request.status === 404).length;
  const accessDeniedCount = errorRequests.filter(
    (request) => request.status === 401 || request.status === 403
  ).length;
  const statusCounts = {};
  for (const request of errorRequests) {
    statusCounts[request.status] = (statusCounts[request.status] || 0) + 1;
  }

  const headers = headerSample || null;
  const ua = userAgent || "";
  const headerObservationAvailable = headers !== null;
  const automationUA = headerObservationAvailable ? isAutomationUA(ua) : false;
  const missingHeaders = headerObservationAvailable ? missingBrowserHeaders(headers) : [];
  const interaction = telemetry || emptyTelemetry();

  const attackRequests = recent(ordered, FEATURE_WINDOWS.attackRequests);
  const allTags = attackRequests.flatMap((request) => request.tags || []);
  const attackCategories = Array.from(new Set(allTags));
  const experimentRunIds = Array.from(
    new Set(ordered.map((request) => request.experimentRunId).filter(Boolean))
  );

  return {
    totalRequests: ordered.length,
    sessionDurationMs: Math.max(0, (lastSeen || 0) - (firstSeen || 0)),
    fingerprint: fingerprint || null,
    userAgent: ua,
    experimentRunIds,
    windows: FEATURE_WINDOWS,
    temporal: {
      timingSampleSize: timingRequests.length,
      avgIntervalMs,
      intervalStdevMs,
      intervalCV,
      maxRequests2s,
      requests10s,
    },
    behavior: {
      recentSequence: sequenceRequests.map((request) => request.operation),
      repeatSampleSize: repeatedRequests.length,
      repeatRatio: repeatedRequests.length ? mostRepeatedCount / repeatedRequests.length : 0,
      maxConsecutiveRepeats: maxConsecutiveRepeats(repeatedOperations),
      diversitySampleSize: diversityRequests.length,
      uniqueNormalizedPaths: uniquePaths.size,
      pathDiversity: diversityRequests.length ? uniquePaths.size / diversityRequests.length : 0,
    },
    exploration: {
      sampleSize: errorRequests.length,
      notFoundCount,
      notFoundRatio: errorRequests.length ? notFoundCount / errorRequests.length : 0,
      accessDeniedCount,
      accessDeniedRatio: errorRequests.length ? accessDeniedCount / errorRequests.length : 0,
      statusCounts,
    },
    client: {
      sessionChurn,
      headerObservationAvailable,
      automationUA,
      missingHeaderCount: missingHeaders.length,
      missingHeaders,
      browserInteraction: {
        mouseMoveCount: interaction.mouseMoveCount,
        scrollCount: interaction.scrollCount,
        domEventDiversity: interaction.domEventTypes.size,
        pageLoads: interaction.pageLoads,
        hasTelemetry: interaction.lastTelemetryAt !== null,
      },
    },
    attack: {
      sampleSize: attackRequests.length,
      payloadSignatureHits: allTags.length,
      distinctPayloadCategories: attackCategories.length,
      payloadCategories: attackCategories,
    },
  };
}

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

function extractActorFeatures(actor, getSession) {
  const memberSessions = Array.from(actor.sessionIds, (id) => getSession(id)).filter(Boolean);
  return extractStreamFeatures({
    requests: actor.requests,
    headerSample: actor.headerSample,
    fingerprint: actor.fingerprint,
    userAgent: actor.userAgent,
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: actor.firstSeen,
    lastSeen: actor.lastSeen,
    sessionChurn: actor.sessionIds.size,
  });
}

function extractAuthGroupFeatures(group, getSession) {
  const memberSessions = Array.from(group.sessionIds, (id) => getSession(id)).filter(Boolean);
  const representative = memberSessions.find((session) => session.headerSample) || memberSessions[0];
  return extractStreamFeatures({
    requests: group.requests,
    headerSample: representative ? representative.headerSample : null,
    fingerprint: representative ? representative.fingerprint : null,
    userAgent: representative ? representative.userAgent : "",
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: group.firstSeen,
    lastSeen: group.lastSeen,
    sessionChurn: group.sessionIds.size,
  });
}

function extractIpFeatures(ipEntry, getSession) {
  const memberSessions = Array.from(ipEntry.sessionIds, (id) => getSession(id)).filter(Boolean);
  return extractStreamFeatures({
    requests: ipEntry.requests,
    headerSample: null,
    fingerprint: null,
    userAgent: "",
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: ipEntry.firstSeen,
    lastSeen: ipEntry.lastSeen,
    sessionChurn: ipEntry.sessionIds.size,
  });
}

module.exports = {
  extractFeatures,
  extractActorFeatures,
  extractAuthGroupFeatures,
  extractIpFeatures,
  extractStreamFeatures,
  aggregateTelemetry,
  mean,
  stdev,
  maxBurst,
  maxRequestsInWindow,
};

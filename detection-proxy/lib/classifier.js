// 각 feature -> 0(사람같음) ~ 1(봇/AI같음) 정규화 함수
// clamp helper
const clamp = (x, lo = 0, hi = 1) => Math.min(hi, Math.max(lo, x));

function scoreInterval(f) {
  // 너무 빠르거나(사람 반응속도 이하) 너무 규칙적이면(CV 낮음) 봇 의심
  if (f.totalRequests < 3) return 0;
  const fastScore = clamp(1 - f.avgIntervalMs / 800); // 800ms 이하일수록 점수 상승
  const regularityScore = clamp(1 - f.intervalCV / 0.6); // CV가 0.6보다 작을수록(규칙적) 점수 상승
  return clamp(0.6 * fastScore + 0.4 * regularityScore);
}

function scoreUrlDiversity(f) {
  // 짧은 시간에 매우 다양한 경로를 두드리면(엔드포인트 스캐닝) 봇 의심
  if (f.totalRequests < 10) return 0;
  return clamp((f.urlDiversity - 0.5) / 0.5);
}

function scoreNotFound(f) {
  // 404 비율이 높으면 무차별 fuzzing/enumeration 의심
  return clamp(f.notFoundRatio / 0.4);
}

function scoreHeaderFingerprint(f) {
  let s = 0;
  if (f.automationUA) s += 0.6;
  s += clamp(f.missingHeaderCount / 4) * 0.4;
  return clamp(s);
}

function scorePayloadSignature(f) {
  // 내용 기반 탐지: 요청에 공격 페이로드 시그니처(SQLi/XSS/NoSQL/path-traversal 등)가
  // 있으면 세션/행동 신호와 무관하게 단독으로 강하게 봇/공격으로 판정한다.
  if (!f.attackSignatureHits) return 0;
  const variety = clamp((f.distinctAttackCategories - 1) / 3) * 0.3; // 공격 종류가 다양할수록 가중
  return clamp(0.7 + variety);
}

function scoreMouseMove(f) {
  // 앱 요청은 여러 번 하면서 텔레메트리 비콘이 한 번도 안 왔다 = JS 미실행 = 강한 봇 신호.
  // (기존엔 중립 0.5로 처리해 curl류 공격이 임계값 아래로 빠져나갔다)
  if (!f.hasTelemetry) return f.totalRequests >= 3 ? 0.9 : 0.5;
  if (f.totalRequests < 5) return 0;
  return f.mouseMoveCount === 0 ? 1 : clamp(1 - f.mouseMoveCount / 30);
}

function scoreScroll(f) {
  if (!f.hasTelemetry) return f.totalRequests >= 3 ? 0.9 : 0.5;
  if (f.totalRequests < 5) return 0;
  return f.scrollCount === 0 ? 1 : clamp(1 - f.scrollCount / 10);
}

function scoreDomDiversity(f) {
  if (!f.hasTelemetry) return 0.5;
  if (f.totalRequests < 5) return 0;
  // click/keydown/focus 등 다양한 이벤트 종류가 나올수록 사람일 가능성
  return clamp(1 - f.domEventDiversity / 5);
}

function scoreBurst(f) {
  // 2초 윈도우 안에 요청이 몰릴수록 자동화 의심 (사람은 클릭 간 지연이 있음)
  return clamp((f.burstLength - 3) / 12);
}

function scoreSessionChurn(f) {
  // 같은 IP에서 세션 쿠키가 계속 바뀐다 = 쿠키를 보존하지 않는 스크립트일 가능성
  return clamp((f.sessionChurn - 1) / 9);
}

const WEIGHTS = {
  payloadSignature: 0.30, // 내용 기반 탐지에 최대 가중 - 세션 수와 무관하게 공격을 잡는다
  headerFingerprint: 0.15,
  interval: 0.10,
  notFound: 0.10,
  mouseMove: 0.10,
  burst: 0.08,
  urlDiversity: 0.07,
  sessionChurn: 0.05,
  scroll: 0.03,
  domDiversity: 0.02,
};

function classify(features) {
  const breakdown = {
    payloadSignature: scorePayloadSignature(features),
    interval: scoreInterval(features),
    urlDiversity: scoreUrlDiversity(features),
    notFound: scoreNotFound(features),
    headerFingerprint: scoreHeaderFingerprint(features),
    mouseMove: scoreMouseMove(features),
    scroll: scoreScroll(features),
    domDiversity: scoreDomDiversity(features),
    burst: scoreBurst(features),
    sessionChurn: scoreSessionChurn(features),
  };

  let score = 0;
  for (const key of Object.keys(WEIGHTS)) {
    score += WEIGHTS[key] * breakdown[key];
  }
  score = clamp(score);

  let label = "human";
  if (score >= 0.7) label = "likely-ai-bot";
  else if (score >= 0.4) label = "suspicious";

  return { score: Number(score.toFixed(3)), label, breakdown };
}

module.exports = { classify, WEIGHTS };

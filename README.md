# Juice Shop AI 공격자 탐지 레이어

OWASP Juice Shop 앞단에 붙는 리버스 프록시형 탐지 레이어입니다.
모든 요청/응답을 가로채 세션 단위로 행동 데이터를 쌓고, 규칙 기반 가중치 스코어링으로
"사람 / 의심 / AI·봇 공격자"를 실시간으로 분류합니다.

```
Browser / AI Agent ──▶ detection-proxy (:8080) ──▶ juice-shop (:3000)
                              │
                              ├─ 요청 로그 (세션 쿠키 dlsid 기준)
                              ├─ HTML 응답에 telemetry.js 자동 주입
                              ├─ POST /__detection/telemetry 로 마우스/스크롤/DOM 이벤트 수집
                              └─ GET  /__detection/dashboard  실시간 대시보드
```

## 실행

```bash
docker compose up --build
```

- 앱 접속: http://localhost:8080  (Juice Shop이 이 포트를 통해 프록시됨)
- 탐지 대시보드: http://localhost:8080/__detection/dashboard
- 세션 API: http://localhost:8080/__detection/api/sessions

## 사용한 탐지 Feature

| Feature | 설명 | 위치 |
|---|---|---|
| 평균 요청 간격 / 규칙성(CV) | 너무 빠르거나(사람 반응속도 이하) 간격이 지나치게 일정하면 봇 의심 | `featureExtractor.js` → `avgIntervalMs`, `intervalCV` |
| URL 다양성 | 짧은 시간에 매우 다양한 경로를 두드리면 엔드포인트 스캐닝(AI 정찰) 의심 | `urlDiversity` |
| 404 비율 | 존재하지 않는 경로 요청 비율이 높으면 무차별 fuzzing/enumeration 의심 | `notFoundRatio` |
| 헤더 Fingerprint | User-Agent가 자동화 도구(curl/python-requests/Playwright 등) 패턴이거나, 실브라우저가 항상 보내는 `Sec-Fetch-*`, `Accept-Language` 헤더가 없으면 의심 | `uaSignatures.js` |
| Mouse Move 수 | 페이지 응답을 받고도 마우스 이동이 전혀 없으면 강한 봇 신호 | `telemetry.js` → `mouseMoveCount` |
| Scroll 이벤트 | 스크롤이 전혀 없으면 봇 의심 | `scrollCount` |
| DOM 이벤트 다양성 | click/keydown/focus 등 이벤트 종류가 다양할수록 사람일 가능성 | `domEventDiversity` |
| 요청 Burst 길이 | 2초 슬라이딩 윈도우 내 최대 요청 수. 사람은 클릭 간 지연이 있음 | `maxBurst()` |
| (추가) 세션 Churn | 같은 IP에서 세션 쿠키가 계속 바뀌면 쿠키를 보존하지 않는 스크립트일 가능성 | `sessionChurn` |

각 feature는 0(사람 같음)~1(봇 같음)로 정규화된 뒤 가중합으로 최종 score(0~1)를 산출합니다
(`lib/classifier.js`의 `WEIGHTS` 참고).

- `score < 0.4` → `human`
- `0.4 ≤ score < 0.7` → `suspicious`
- `score ≥ 0.7` → `likely-ai-bot`

## 공격 경로(타임라인) 보기

대시보드(`/__detection/dashboard`)에서 세션 행을 클릭하면 그 세션이 시간순으로
어떤 엔드포인트를 어떤 순서로 찔렀는지, 어떤 body(payload)를 보냈는지, 그리고
알려진 공격 패턴(SQLi/XSS/path traversal/command injection/SSTI/NoSQLi/JWT 조작/IDOR probe)에
해당하는지 태그와 함께 볼 수 있습니다.

API로 직접 조회하려면:

```bash
# 특정 세션의 전체 요청 타임라인
curl http://localhost:8080/__detection/api/sessions/<sessionId>/path

# 전체 세션 로그 export (리포트 작성용)
curl http://localhost:8080/__detection/api/export -o detection-log-export.json
```

각 요청 로그 항목은 `{ ts, method, url, status, body, tags }` 형태이며,
`body`는 최대 2000자로 잘려 저장됩니다(메모리 보호). `tags`는 `lib/payloadSignatures.js`에
정의된 정규식으로 자동 태깅되며, 필요에 맞게 시그니처를 추가/수정할 수 있습니다.

> 참고: 로그인 폼 등 POST body는 `express.json()`/`urlencoded()`로 한 번 파싱한 뒤
> `fixRequestBody()`로 다시 스트림에 실어 juice-shop으로 정상 전달합니다(그래야 로그인 등
> 실제 앱 동작이 깨지지 않습니다).

## 자동 차단 (선택)

기본은 탐지·로깅만 수행합니다. 실제로 차단하려면 `docker-compose.yml`에서:

```yaml
environment:
  - BLOCK_MODE=true
  - BLOCK_THRESHOLD=0.75   # 이 점수 이상이면 403 반환
```

## 한계 및 개선 방향

- 현재는 **인메모리 저장소**라 프록시 재시작 시 세션 데이터가 초기화됩니다. 장기 운영 시 Redis 등으로 교체 권장.
- 규칙 기반 가중합 방식이라 임계치/가중치는 실제 트래픽으로 튜닝이 필요합니다. `lib/classifier.js`의 `WEIGHTS`, 각 `score*()` 함수의 정규화 상수를 조정하세요.
- 정교한 AI 에이전트(마우스를 인위적으로 흔드는 컴퓨터 사용 에이전트 등)에 대응하려면 마우스 이동의 **궤적 자연스러움**(가속도, 곡률, jitter)까지 분석하는 고급 feature 추가를 권장합니다.
- 텔레메트리는 JS를 실행하는 클라이언트에서만 수집됩니다. JS를 실행하지 않는 순수 HTTP 클라이언트(대부분의 스크립트/curl 기반 AI 에이전트)는 `hasTelemetry=false`로 별도 취급되며, 이 자체도 강한 신호로 반영됩니다.

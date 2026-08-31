# Juice Shop AI 공격자 탐지 레이어

OWASP Juice Shop을 기본 대상으로 실행하지만 `TARGET_URL`을 바꾸면 다른 HTTP 웹 서비스
앞단에도 붙일 수 있는 리버스 프록시형 탐지 레이어입니다.
모든 요청/응답을 가로채 집계 단위별 행동 데이터를 쌓고, 자동화 징후와 공격 징후를
서로 독립된 heuristic Score로 제공합니다. 이 값은 사람이나 AI를 확정하는 확률이 아닙니다.

```
Browser / AI Agent ──▶ detection-proxy (:8080) ──▶ juice-shop (:3000)
                              │
                              ├─ ModSecurity 3.0.16 + OWASP CRS 4.25.1 (탐지 전용)
                              ├─ 팀원 Honey/Deception 탐지 (동일 Node 프로세스)
                              ├─ Session 로그 (세션 쿠키 dlsid 기준)
                              ├─ Client Actor 집계 (IP + 헤더 fingerprint 기준)
                              ├─ Auth Group 집계 (동일 Bearer token hash 기준)
                              ├─ IP Entry 관찰 (동일 IP 전체, 점수/차단 제외)
                              ├─ HTML 응답에 telemetry.js 자동 주입
                              ├─ POST /__detection/telemetry 로 마우스/스크롤/DOM/SPA 이동 수집
                              └─ GET  /__detection/dashboard  실시간 대시보드
```

## 실행

```bash
docker compose up --build
```

- 앱 접속: http://localhost:8080  (Juice Shop이 이 포트를 통해 프록시됨)
- 탐지 대시보드: http://localhost:8080/__detection/dashboard
- 세션 API: http://localhost:8080/__detection/api/sessions
- Client Actor API: http://localhost:8080/__detection/api/actors
- Auth Group API: http://localhost:8080/__detection/api/auth-groups
- IP Entry API: http://localhost:8080/__detection/api/ip-entries
- CRS 상태 API: http://localhost:8080/__detection/api/crs-status
- Deception 상태 API: http://localhost:8080/__detection/api/deception-status

외부에 노출되고 요청을 중계하는 프록시는 Node의 `detection-proxy` 하나뿐입니다. Honey/Deception
로직도 이 프로세스의 Express 라우트와 응답 interceptor에서 직접 실행됩니다. ModSecurity는 같은
컨테이너 안에서 지속 실행되는 규칙 평가 helper이며 별도 포트를 열거나 요청을 전달하지
않습니다. `SecRuleEngine DetectionOnly`로 동작하므로 CRS 탐지 결과가 원래 응답을 차단하거나
변경하지 않습니다.

## Feature와 Score

| Feature | 설명 | 위치 |
|---|---|---|
| Temporal | 최근 50개 요청의 평균 간격/CV, 2초 최대 요청 수, 최근 10초 요청 수 | Automation |
| Behavior | 최근 10개 operation, 최근 20개 반복률/최대 연속 반복, 최근 50개 경로 다양성 | 반복만 Automation, 나머지 관찰 |
| Exploration | 최근 50개 요청의 404 비율과 401/403 비율 | Attack |
| Client | Session churn, Header anomaly, 통합 Browser interaction | Automation |
| Attack | 최근 50개 요청의 OWASP CRS 규칙 탐지 결과와 SQLi/XSS/Traversal 등 공격 유형 | Attack |
| Honey/Deception | 자동화형 트랩·coverage와 공격형 워터마크·미끼 자격증명·파일 반응 | Automation/Attack에 각각 최대 35% |

Automation Score는 Timing 5%, Intensity 5%, Repeated Operation 10%, Session Churn 10%,
Header Anomaly 15%, Browser Interaction 20%, Automation Honey 35%로 구성됩니다. Attack Score는
Payload Signature 55%, 404 Exploration 5%, 401/403 Exploration 5%, Attack Honey 35%로
구성됩니다. Sequence는 점수화하지 않습니다.

각 점수는 0~1 내부값을 Dashboard에서 0~100 Score로 표시하는 실험 전 휴리스틱이며 확률이 아닙니다.
Agentic Evidence도 원시 count로만 제공하며 별도 점수, 가중치, AI Agent 라벨을 생성하지 않습니다.

Honey 신호도 AI 여부나 공격 확률의 증명이 아닙니다. 팀원이 제공한 미끼 콘텐츠에 반응한 행위를
Automation 또는 Attack의 보조 근거로 반영합니다. 같은 신호가 반복돼도 점수에는 고유 신호 1회만
반영하고 반복 횟수는 `signalCounts`와 `totalEvents`에 별도로 보존합니다.

브라우저 텔레메트리는 문서와 내부 요소의 스크롤을 capture 단계에서 수집합니다. SPA 화면 이동은
`history.pushState`, `history.replaceState`, `popstate`, `hashchange`를 관찰하며, 현재 URL에는
query와 hash 경로를 포함합니다. `pageLoads`는 5초 주기 전송 횟수가 아니라 실제 문서에서
텔레메트리 스크립트가 처음 실행된 횟수만 집계합니다. SPA 내부 이동 횟수는
`routeChangeCount`로 별도 제공합니다.

## 공격 경로(타임라인) 보기

대시보드(`/__detection/dashboard`)에서 세션 행을 클릭하면 그 세션이 시간순으로
어떤 엔드포인트를 어떤 순서로 찔렀는지, 어떤 body(payload)를 보냈는지, 그리고
알려진 공격 패턴(SQLi/XSS/path traversal/command injection 등)에
해당하는지 태그와 함께 볼 수 있습니다.

API로 직접 조회하려면:

```bash
# 특정 세션의 전체 요청 타임라인
curl http://localhost:8080/__detection/api/sessions/<sessionId>/path

# 전체 세션 로그 export (리포트 작성용)
curl http://localhost:8080/__detection/api/export -o detection-log-export.json
```

각 요청 로그에는 `sessionId`, `actorId`, `authGroupId`, `normalizedPath`, `operation`,
`payloadFingerprint`, `hasAuthorization`, `experimentRunId`가 포함됩니다.
`body`는 최대 2000자로 잘려 저장됩니다(메모리 보호). 정상 컨테이너 환경에서는 OWASP CRS가
URI·헤더·지원되는 요청 본문을 검사해 `attackDetection`, rule ID, anomaly score와 공격 유형을
기록합니다. CRS가 비활성화되거나 실행되지 못한 경우에만 기존 `lib/payloadSignatures.js`의
정규식을 최근 Attack Score용 fallback으로 사용하며, fallback 결과는 CRS 누적 이력에 넣지 않습니다.
Authorization, Proxy-Authorization, Cookie와 실험 식별자 원문은 CRS helper로 전달하지 않습니다.

`normalizedPath`는 query를 제거하고 숫자 경로 segment를 `:id`, UUID를 `:uuid`로 바꿉니다.
`payloadFingerprint`는 canonical payload의 HMAC-SHA256이며 키는 `PAYLOAD_FINGERPRINT_KEY`로
주입합니다. 키가 없으면 프로세스 수명 동안만 유효한 임시 키를 사용하고 경고를 출력합니다.

요청·응답 형식과 크기는 `requestContentType`, `requestContentLength`, `requestBodyBytes`,
`responseContentType`, `responseContentLength`, `responseBodyBytes`로 기록합니다. `ContentLength`는
헤더에 선언된 크기이고 `BodyBytes`는 프록시가 본문을 처리하면서 관찰한 크기입니다. JSON과
URL-encoded 요청의 `requestBodyBytes`는 body parser가 읽은 원본 buffer 기준이며, 파싱하지 않는
multipart·바이너리 요청은 `null`일 수 있습니다. `responseBodyBytes`는 HTML telemetry 주입 전
프록시 응답 buffer 기준입니다. 이 값들은 관찰 전용이며 Score에는 반영하지 않습니다.

## OWASP CRS와 누적 공격 이력

최근 Attack Score는 기존처럼 최근 50개 요청을 사용하므로 정상 요청이 이어지면 낮아질 수 있습니다.
이와 별도로 Session, Actor Candidate, Auth Group에는 `attackHistory`를 유지합니다.

- `hasAttackHistory`: CRS 공격 규칙이 한 번이라도 탐지됐는지
- `maxAttackScore`: 해당 집계 단위에서 관찰된 과거 최고 Attack Score
- `maxCrsAnomalyScore`: 단일 요청의 과거 최고 CRS anomaly score
- `cumulativeRuleHits`: 누적 CRS 공격 규칙 탐지 수
- `matchedRuleIds`, `attackCategories`: 지금까지 탐지된 규칙과 공격 유형
- `firstAttackAt`, `lastAttackAt`: 최초·최근 CRS 공격 탐지 시각

따라서 공격 요청이 최근 50개 윈도우 밖으로 밀려나도 누적 이력은 유지됩니다. 다만 저장소가
현재 인메모리이므로 “누적” 범위는 프록시 프로세스가 실행 중인 동안이며 재시작 후 영구 보존이
필요하면 Redis나 데이터베이스 저장을 추가해야 합니다. 대시보드 목록의 `Attack History`와
각 상세 화면에서 현재 점수와 누적 이력을 분리해 확인할 수 있습니다.

CRS는 `application/json`, `application/*+json`, URL-encoded 원문 본문을 최대 1 MiB까지 검사하며 URI와 비민감 헤더는 요청 형식과
무관하게 검사합니다. 현재 스트림을 별도로 복제하지 않는 multipart·임의 바이너리 요청은 URI와
헤더만 CRS 검사 대상이며 본문 검사는 추후 보완 범위입니다. `CRS_MAX_BODY_BYTES`와
`CRS_SCAN_TIMEOUT_MS`로 상한을 조정할 수 있습니다.

CRS는 기존 payload signature의 입력 출처를 범용 규칙으로 확장하고, 누적 이력은 현재 점수와
별도 관찰값으로 제공합니다. Honey 통합에 따라 `AUTOMATION_WEIGHTS`와 `ATTACK_WEIGHTS`는 각각
기존 Feature 65%, Honey 35% 구조로 조정했습니다.

## 통합 Honey/Deception 탐지

팀원 저장소 `detection/proxy/detect_proxy/Detect_proxy.py`의 커밋 `4e0e791`에서 검증한 신호
조건과 미끼 문구를 현재 Node 프록시의 `lib/deceptionEngine.js`로 이식했습니다. Python FastAPI,
별도 프록시, `connect.sid`, SQLite 점수 저장소는 실행하지 않습니다.

- `watermark_reuse`: 세션별 ZWJ 워터마크가 이후 요청 본문에서 재사용됨
- `ssh_cred_reuse`, `password_list_reuse`: HTML에 제공한 미끼 자격증명이 재사용됨
- `trap_trigger`: 세션별 토큰이 포함된 off-screen 링크에 접근함
- `writable_file_found`, `writable_file_write`: 미끼 설정 파일 조회·쓰기 시도
- `script_hint_access`: HTML에 언급된 미끼 유지보수 스크립트 접근
- `no_asset_loading`, `trap_trigger`: Automation Honey에 반영
- `coverage`: 최근 50개 요청의 고유 API 경로가 10개 이상이고 자동화 정황이 있을 때 Automation Honey에 조건부 반영
- 나머지 워터마크·자격증명·파일·스크립트 신호: Attack Honey에 반영

세션별 워터마크는 전역 토큰 registry에 발급 세션을 보존하므로 curl이 `dlsid`를 재사용하지 않아도
본문에 워터마크가 있으면 원래 발급 세션을 `originSessionId`로 연결할 수 있습니다. registry와
Deception 이력은 현재 인메모리이므로 프로세스 재시작 후에는 초기화됩니다. 원문 워터마크는
이벤트 detail과 요청 body 로그에서 `[DECEPTION_WATERMARK_REDACTED]`로 대체합니다.

Automation Honey는 `trap_trigger` 20점, `no_asset_loading` 8점, 조건부 `coverage` 최대 7점으로
최대 35점입니다. Attack Honey는 `watermark_reuse` 20점, `writable_file_write` 20점,
`ssh_cred_reuse`·`password_list_reuse` 각 12점, `writable_file_found` 8점,
`script_hint_access` 5점을 합산해 최대 35점으로 제한합니다. 예를 들어 같은 `trap_trigger`가
4번 발생해도 Automation Score에는 20점만 반영되고 `totalEvents`와 `signalCounts`에는 실제
4회가 보존됩니다.

```yaml
environment:
  - DECEPTION_ENABLED=true
  - DECEPTION_TOKEN_TTL_MS=3600000
  - DECEPTION_MAX_SESSIONS=5000
```

## Authorization Auth Group

프록시 요청의 `Authorization: Bearer <token>`은 raw token을 저장하지 않고 전체
SHA-256 hash인 `auth:<64자리 hex>`로 즉시 변환됩니다. 같은 token을 사용한 요청은
`dlsid`가 달라도 동일 Auth Group에 기록되며, Authorization이 없는 요청의
`authGroupId`는 `null`입니다. Auth Group은 그룹에 속한 모든 요청과 세션 텔레메트리를
하나의 인증 흐름으로 집계해 Automation/Attack Score를 계산합니다. Agentic Evidence는
Actor별로 먼저 계산한 뒤 합산하므로 서로 다른 Actor의 transition을 연결하지 않습니다. 대시보드에서
Auth Group 행을 클릭하면 그룹 전체의 시간순 공격 경로를 볼 수 있습니다.

```bash
curl http://localhost:8080/__detection/api/auth-groups
curl http://localhost:8080/__detection/api/auth-groups/<authGroupId>
curl http://localhost:8080/__detection/api/auth-groups/<authGroupId>/path
```

## Client Actor Candidate

Session 표는 각 `dlsid`에 기록된 요청만으로 점수를 계산합니다. 쿠키를 보존하지 않는
CLI/스크립트 요청은 `IP + 헤더 fingerprint(User-Agent, Accept, Accept-Language,
Accept-Encoding)`로 만든 Client Actor에서 별도로 합산합니다. 따라서 Docker/NAT에서
동일 IP로 보이는 브라우저와 curl이 한 행으로 합쳐지지 않으면서, 같은 curl이 매 요청마다
새 `dlsid`를 발급받는 session churn은 계속 탐지할 수 있습니다. 이 그룹은 실제 사용자를
확정하는 ID가 아니라 heuristic actor candidate입니다.

```bash
curl http://localhost:8080/__detection/api/actors
curl http://localhost:8080/__detection/api/actors/<actorId>
curl http://localhost:8080/__detection/api/actors/<actorId>/path
```

IP Entry는 동일 IP 요청을 관찰하기 위한 별도 집계이며 NAT/Docker 혼합 가능성 때문에
Automation/Attack Score와 차단 기준에 사용하지 않습니다.

> 참고: 로그인 폼 등 POST body는 `express.json()`/`urlencoded()`로 한 번 파싱한 뒤
> `fixRequestBody()`로 다시 스트림에 실어 juice-shop으로 정상 전달합니다(그래야 로그인 등
> 실제 앱 동작이 깨지지 않습니다).

## Log-only와 실험 Run ID

현재 버전은 `BLOCK_MODE=true`여도 임계치 이상 탐지 결과를 로그로만 기록하며 응답을 403으로
변경하지 않습니다. FPR/FNR 검증 후 별도 차단 정책을 결정할 예정입니다.

실험 환경에서는 다음 설정과 헤더로 ground truth 구간을 표시할 수 있습니다.

```yaml
environment:
  - ENABLE_EXPERIMENT_RUN_ID=true
```

```http
X-Experiment-Run-Id: codex-run-001
```

Run ID는 형식 검증 후 요청 레코드에만 저장되며 Feature, Score, Actor 식별에 사용되지 않습니다.
프록시는 이 헤더를 Juice Shop target으로 전달하지 않습니다.

## 한계 및 개선 방향

- 현재는 **인메모리 저장소**라 프록시 재시작 시 세션 데이터가 초기화됩니다. 장기 운영 시 Redis 등으로 교체 권장.
- 규칙 기반 가중합 방식이라 임계치/가중치는 실제 트래픽으로 튜닝이 필요합니다. `lib/classifier.js`의 `AUTOMATION_WEIGHTS`, `ATTACK_WEIGHTS`, `NORMALIZATION`을 조정하세요.
- 정교한 AI 에이전트(마우스를 인위적으로 흔드는 컴퓨터 사용 에이전트 등)에 대응하려면 마우스 이동의 **궤적 자연스러움**(가속도, 곡률, jitter)까지 분석하는 고급 feature 추가를 권장합니다.
- 텔레메트리는 JS를 실행하는 클라이언트에서만 수집됩니다. JS를 실행하지 않는 순수 HTTP 클라이언트(대부분의 스크립트/curl 기반 AI 에이전트)는 `hasTelemetry=false`로 별도 취급되며, 이 자체도 강한 신호로 반영됩니다.

## 오픈소스 및 라이선스

컨테이너 빌드는 Apache License 2.0인 OWASP ModSecurity `v3.0.16`과 OWASP Core Rule Set
`v4.25.1`의 고정 commit을 사용합니다. 버전, source와 라이선스는
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)에 기록했습니다. 프로젝트 전용 adapter,
누적 집계, API와 대시보드 로직은 외부 구현을 복사한 코드가 아닙니다.

# 실험 5 자동화

회원가입, 로그인, 인증 사용자 확인 및 리뷰 작성 시나리오를 Codex 또는 Claude로 실행한다.
실행마다 탐지 로그 JSON, 렌더링된 대시보드 HTML 3종, 추론 기록과 검증 결과를 저장한다.

```bash
scripts/experiment5/run.sh --subject codex --run 1
scripts/experiment5/run.sh --subject claude --run 1
```

기존 Compose 상태를 유지하려면 `--no-reset`을 추가할 수 있다. 동일 스택에서 여러 실험을
병렬로 실행하면 로그가 섞이므로 순차 실행한다. 사람 실험은 실제 조작을 사람이 수행해야
하므로 이 실행기의 Agent 실행 대상으로 포함하지 않는다.

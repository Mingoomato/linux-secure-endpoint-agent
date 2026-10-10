# 독립 코딩 실습 — Linux Secure Endpoint Agent Lab

아래 세 과제에는 정답 코드나 완성 패치가 없습니다. 과제를 먼저 직접 구현한 뒤에만 본인 기록에 결과와 설명을 남기세요. 인증서는 저장소 밖의 임시 디렉터리에서 만들고, server/client 모두 loopback에서만 실행합니다. 안전 경계를 약화하거나 파일 수집·원격 명령 기능을 추가하지 마세요.

## 실습 1 — `event.v1` import privacy 경계

**목표:** event.v1 path가 정책 scope 안에 있는지 검증하고, queue에 원문 경로나 대상 파일 내용이 들어가지 않는지 독립적으로 재현합니다.

**시작점:** `contracts/event-v1.schema.json`, `normalize_imported_event`, `pseudonymize_path`, `tests/smoke.sh`.

허용 root 안의 경로, root 밖 경로, 민감한 추가 필드, 재사용 event ID를 가진 작은 입력 픽스처를 만드세요. 별도 임시 store에서 import 전후 SQLite queue를 비교하고, 같은 경로가 같은 store에서 일관된 pseudonym을 내는지, 원문 path와 target-file marker가 payload에 없는지 확인하세요.

**완료 기준:** 허용 이벤트만 bounded durable queue에 들어가고, 원문 경로·파일 내용은 저장되지 않으며, scope 위반·unknown field·다른 내용의 event ID 재사용이 거부된다는 자동 검증이 있습니다.

## 실습 2 — 잘못된 새 정책과 last-good 유지

**목표:** 만료됐거나 scope가 잘못된 새 서명 정책이 이전의 유효 정책 상태를 덮지 않는지 검증합니다.

**시작점:** `validate_signed_policy`, `policy_state`, `tests/smoke.sh`의 정책 fixture.

유효 revision을 먼저 저장한 뒤 더 높은 revision의 만료/잘못된 tenant 정책을 각각 검증하세요. 실패한 시도 이후 SQLite의 revision과 문서가 기존 값으로 남는지 확인하고, 후속 유효 revision을 계속 적용할 수 있는지도 기록하세요.

**완료 기준:** 실패한 정책 시도 전후의 last-good DB 값이 같고, 새 유효 revision이 정상적으로 저장된다는 자동 검증이 있습니다.

## 실습 3 — 큐 용량 초과와 내구성 경계

**목표:** 행 수 또는 저장 byte 제한에 도달했을 때 새 event enqueue가 기존 durable row를 손상시키거나 조용히 버리지 않도록 독립 회귀 검증을 추가합니다.

**시작점:** `agent/src/agent.cpp`의 queue quota 검사와 enqueue 경로, `tests/smoke.sh`, 임시 SQLite store.

임시 store의 한도를 작게 설정하거나 quota 검사 단위를 분리해, 행 한도와 byte 한도를 각각 경계 직전·정확히 가득 찬 상태·초과 상태로 재현하세요. 각 시도 전후에 저장된 row 수와 payload를 비교하고, server 연결이 불가능한 경우에도 이미 commit된 row가 보존되는지 확인하세요.

**완료 기준:** 두 quota 경계에서 허용/거부 결과와 SQLite queue의 기존 내용이 자동 검증되고, 초과 거부가 데이터 유실이나 부분 row를 만들지 않는다는 assertion이 있습니다.

## 본인 재현 기록

선택한 과제, 직접 작성한 설계 메모, 실행한 검증 명령과 결과, 발견한 보안/복구 한계를 개인 학습 기록에 남기세요. 아직 소유자의 독립 구현을 관찰하지 않았으므로 현재 재현 상태는 **증거 없음**입니다.

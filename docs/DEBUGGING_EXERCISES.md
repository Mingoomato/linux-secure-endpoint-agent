# 독립 코딩 실습 — Linux Secure Endpoint Agent Lab

아래 세 과제에는 정답 코드나 완성 패치가 없습니다. 과제를 먼저 직접 구현한 뒤에만 본인 기록에 결과와 설명을 남기세요. 인증서는 저장소 밖의 임시 디렉터리에서 만들고, server/client 모두 loopback에서만 실행합니다. 안전 경계를 약화하거나 파일 수집·원격 명령 기능을 추가하지 마세요.

## 실습 1 — ACK와 제출 batch의 경계 검증

**목표:** ACK에 현재 batch에 없는 event ID가 섞인 경우, 로컬 queue가 그 ID나 미확인 항목을 제거하지 않음을 독립적으로 검증합니다.

**시작점:** `ack_ids`, `flush`, `delete_acked`, `tests/smoke.sh`.

Loopback TLS test double을 추가하거나 최소한의 ACK 처리 단위를 분리해, 올바른 accepted/duplicate ID와 외부 ID가 함께 있는 ACK를 재현하세요. 보낸 batch에 속하지 않은 ID를 확인하고 각 응답 뒤의 SQLite queue row를 대조하세요.

**완료 기준:** 현재 batch에 속하고 성공/중복으로 확인된 ID만 삭제되며, 미확인 queue 항목은 남는다는 DB 상태 assertion이 있습니다.

## 실습 2 — 잘못된 새 정책과 last-good 유지

**목표:** 만료됐거나 scope가 잘못된 새 서명 정책이 이전의 유효 정책 상태를 덮지 않는지 검증합니다.

**시작점:** `validate_signed_policy`, `policy_state`, `tests/smoke.sh`의 정책 fixture.

유효 revision을 먼저 저장한 뒤 더 높은 revision의 만료/잘못된 tenant 정책을 각각 검증하세요. 실패한 시도 이후 SQLite의 revision과 문서가 기존 값으로 남는지 확인하고, 후속 유효 revision을 계속 적용할 수 있는지도 기록하세요.

**완료 기준:** 실패한 정책 시도 전후의 last-good DB 값이 같고, 새 유효 revision이 정상적으로 저장된다는 자동 검증이 있습니다.

## 실습 3 — 요청 전체의 절대 deadline

**목표:** 부분 데이터를 조금씩 보내 socket의 개별 timeout을 계속 갱신하는 slow client가 한 연결을 무기한 점유하지 못하도록 제한합니다.

**시작점:** `server/src/server.cpp`의 `read_request`·`serve_one`, socket timeout 설정, loopback TLS integration harness.

연결 시작 시 단조 시계 기준 deadline을 설정하고, header/body 일부가 반복 도착해도 같은 총 기한이 적용되도록 구현하세요. TLS loopback client가 정해진 간격으로 byte를 보내는 경우 응답 전 요청이 제한 시간 안에 종료되는지 재현하고, 정상 요청과 timeout 경계를 함께 검사하세요.

**완료 기준:** idle timeout과 전체 요청 deadline의 차이를 검증하는 통합 시험이 있고, 시간 계산은 wall clock 변경에 영향을 받지 않습니다.

## 본인 재현 기록

선택한 과제, 직접 작성한 설계 메모, 실행한 검증 명령과 결과, 발견한 보안/복구 한계를 개인 학습 기록에 남기세요. 아직 소유자의 독립 구현을 관찰하지 않았으므로 현재 재현 상태는 **증거 없음**입니다.

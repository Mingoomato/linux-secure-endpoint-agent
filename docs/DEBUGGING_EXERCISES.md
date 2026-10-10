# 독립 코딩 실습 — Linux Secure Endpoint Agent Lab

아래 세 과제에는 정답 코드나 완성 패치가 없습니다. 과제를 먼저 직접 구현한 뒤에만 본인 기록에 결과와 설명을 남기세요. 인증서는 저장소 밖의 임시 디렉터리에서 만들고, server/client 모두 loopback에서만 실행합니다. 안전 경계를 약화하거나 파일 수집·원격 명령 기능을 추가하지 마세요.

## 실습 1 — telemetry의 JSON Content-Type 계약

**목표:** batch endpoint의 미디어 타입 계약을 문서화하고 대소문자와 공백 경계에 대한 회귀 테스트를 추가합니다.

**시작점:** `Request`, `read_request`, `serve_one`, `tests/smoke.sh`.

현재 코드는 `application/json`만 허용합니다. header 이름과 media type 대소문자 변형, 앞뒤 공백, charset parameter를 테스트하고 어떤 형식을 허용할지 계약으로 정하세요. 필요한 parser 동작과 문서를 구현하고, 누락/잘못된 Content-Type의 batch가 DB에 기록되지 않는 것을 확인하세요.

**완료 기준:** 기존 정상 batch와 동작이 호환되고, 잘못된 미디어 타입이 안전하게 거부되며, DB 상태를 검사하는 통합 테스트가 있습니다.

## 실습 2 — Agent의 HTTP 응답 상태 처리

**목표:** TLS mock response를 이용해 HTTP status와 ACK JSON의 분리된 검증을 재현합니다.

**시작점:** `http_exchange`, `ack_ids`, `send_batch`, `flush`, loopback TLS test helpers.

정상 200 ACK, HTTP 204/400/500, 잘못된 status line, ACK 배열이 들어 있는 비성공 응답을 생성하는 loopback TLS test double을 추가하세요. 각 응답에서 로컬 queued event가 지워지지 않는지 확인하세요.

**완료 기준:** 성공·실패 status 경계가 테스트에서 구분되고, 오류 본문에 ACK 배열이 있더라도 비성공 응답으로 큐 항목을 삭제하지 않습니다.

## 실습 3 — 요청 head parser의 독립 단위 테스트

**목표:** request line/header 해석을 body socket read와 분리해 테스트하기 쉬운 작은 경계로 만듭니다.

**시작점:** `read_request`의 request-line 및 header 검사, `tests/smoke.sh`, CMake CTest 설정.

유효한 GET/POST head와 빈 헤더, folded header, 중복 Content-Length, Transfer-Encoding, oversized header, 숫자 overflow를 포함하는 table-driven 테스트를 추가하세요. framing 정책은 RFC 9112와 프로젝트의 제한 subset에 맞게 기록하세요.

**완료 기준:** 각 유효 입력과 거부 입력이 자동으로 검증되고, socket I/O 테스트 없이도 head 해석 회귀를 확인할 수 있습니다.

## 본인 재현 기록

선택한 과제, 직접 작성한 설계 메모, 실행한 검증 명령과 결과, 발견한 보안/복구 한계를 개인 학습 기록에 남기세요. 아직 소유자의 독립 구현을 관찰하지 않았으므로 현재 재현 상태는 **증거 없음**입니다.

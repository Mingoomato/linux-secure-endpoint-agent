# 기술 방어 질문 — Linux Secure Endpoint Agent Lab

정답지는 포함하지 않습니다. 각 답변에서는 관련 코드 경로, 관찰한 테스트, 실패 시 데이터 상태를 근거로 설명하세요.

## 코드 읽기와 데이터 흐름

1. `next_sequence`와 `enqueue`부터 `queue` row가 저장될 때까지 호출 순서를 설명하세요.
2. 왜 event를 network 전 SQLite에 저장하나요? queue commit과 서버 ACK 사이에는 어떤 실패 구간이 있나요?
3. `send_batch`가 DNS/IP 결과 중 loopback을 고르고 서버 SAN 검증을 설정하는 흐름을 설명하세요.
4. mTLS handshake에서 client와 server 각각 무엇을 인증하며, 그 뒤 allowlist는 어떤 별도 판단을 하나요?
5. client 인증서 CN, allowlist, request body의 `agent_id` 세 값이 어떻게 비교되나요?
6. `ingest` transaction은 언제 commit되고, 어떤 시점 이후에 ACK가 전송되나요?
7. Agent는 server 응답의 ID를 어떤 제출 batch와 비교한 뒤 queue에서 제거하나요?
8. event payload hash가 계산되는 값과 server가 다시 계산하는 값은 무엇인가요?
9. `validate_signed_policy`는 raw bytes 검증, JSON 검사, UTC expiry 확인, canonical root scope 확인, DB 변경을 어떤 순서로 수행하나요?

## Linux·메모리·실패 분석

10. TCP가 메시지 경계를 제공하지 않는다는 점이 `read_request`와 `http_exchange` 구현에 어떤 영향을 주나요?
11. `SO_RCVTIMEO` 5초 설정이 보장하는 범위와 보장하지 않는 범위를 설명하세요.
12. 예외가 `serve_one` 안에서 발생할 때 `SSL*`와 accepted FD 수명은 어떻게 끝나나요? 잠재적인 누수 경로를 찾으세요.
13. 어떤 SQLite statement가 finalize되지 않으면 어떤 자원이 남나요? transaction rollback이 필요한 실패 경로는 무엇인가요?
14. sequence update와 event insert가 별도 transaction이면 process crash 뒤 어떤 DB 상태가 가능한가요?
15. server가 commit했지만 ACK가 유실되면 다음 시도에서 데이터가 왜 중복 생성되지 않나요?

## 디버깅과 보안 추론

16. 두 개의 서로 다른 Content-Length가 같은 요청에 있을 때 현재 parser가 이를 거부해야 하는 이유는 무엇인가요?
17. `Transfer-Encoding`을 지원하지 않으면서 명시적으로 거부하는 것과 조용히 무시하는 것의 차이는 무엇인가요?
18. body가 선언한 길이보다 짧거나 길 때, 또는 ACK 모양의 JSON을 담은 HTTP 400일 때 parser와 DB 상태가 어떻게 되어야 하나요?
19. 잘못된 SAN과 신뢰되지 않은 CA는 어느 계층에서 실패하고, unregistered CN은 어느 계층에서 실패하나요?
20. 민감 키 이름 blacklist가 개인정보 보호를 완성하지 못하는 이유와 추가해야 할 경계는 무엇인가요?
21. loopback-only bind가 막는 공격과 같은 호스트의 악성 프로세스에 대해 남는 공격면을 각각 설명하세요.
22. queue quota와 disk full은 생성된 event의 내구성 주장에 어떤 영향을 주나요?
23. 서명된 정책을 DB에 저장한 것과 endpoint에서 실제로 적용한 것을 어떻게 구별하나요?

## 설계 대안과 시험 범위

24. custom HTTP parser를 유지하는 것과 검증된 HTTP library를 도입하는 선택을 안전성·학습성·유지보수 관점에서 비교하세요.
25. 순차 server를 bounded worker pool로 바꾸면 FD, TLS handshake, SQLite writer 경합을 어떻게 제한해야 하나요?
26. CN allowlist를 certificate fingerprint나 SAN URI identity로 바꾸면 enrollment와 rotation 설계에 어떤 변화가 필요한가요?
27. DB unique key가 보장하는 멱등성과 네트워크 exactly-once 전달은 어떻게 다른가요?
28. agent/server JSON parser 사본을 별도로 두는 이유와 drift 위험을 줄일 방안을 설명하세요.
29. 현재 GCC/Clang·sanitizer·정적 분석·음성 framing 결과만으로 알 수 없는 SRS 항목은 무엇인가요?
30. 이 저장소의 테스트 통과가 소유자의 개인 숙련도를 증명하지 않는 이유는 무엇이며, 독립 재현의 증거는 어떤 형태여야 하나요?
31. `parse_request_head` 안의 `string_view`가 입력 buffer보다 오래 살아남지 않도록 하는 소유권 경계는 무엇인가요? 반환 `Request`는 어떤 필드를 복사하나요?
32. 100,000회 libFuzzer 실행이 parser 안전성에 제공하는 근거와, 전체 RFC 적합성·장기 안정성에 대해 말해 주지 못하는 점을 구분하세요.
33. allowlist 경로에서 문자열 prefix 비교가 `..`와 symlink에 취약한 이유는 무엇이며, 현재 구현은 어떤 경로 비교를 하나요?
34. policy의 `expires_at`에 달력상 존재하지 않는 날짜나 trailing text를 넣으면 어떤 단계에서 거부되어야 하나요? 실패한 시험은 `policy_state`에 어떤 영향을 줘야 하나요?
35. canonical path 검사를 마친 뒤 실제 runtime monitor가 그 경로를 열기까지 남는 TOCTOU 위험은 무엇이며, 어떤 Linux 인터페이스로 줄일 수 있나요?
36. `SO_RCVTIMEO`가 각 read를 제한해도 느린 peer가 전체 request 수명을 늘릴 수 있는 이유는 무엇인가요? 절대 deadline은 어떤 시계로 계산해야 하나요?
37. ACK에 제출하지 않은 event ID가 포함되면 DB delete가 어떤 기준으로 제한되며, 왜 server response를 그대로 신뢰하면 안 되나요?
38. 만료 정책을 거부하는 것과 이전 revision을 유지하는 것은 서로 어떤 별개의 불변 조건인가요?
39. 이 저장소의 `enroll` 또는 `doctor` 응답이 실제 server-side enrollment를 증명하는지 코드에서 어떻게 판별하나요?
40. JSON revision을 `double`에서 unsigned/SQLite 정수로 바꾸기 전에 양의 정수성과 안전 정밀도 범위를 검사해야 하는 이유는 무엇이며, 거부 시 어떤 last-good 상태를 확인해야 하나요?

## 정책 제어면 추가 방어

41. `/v1/admin/policies` 처리에서 operator certificate allowlist, bearer token, tenant scope 검사는 각각 어떤 위협을 다루며 왜 서로 대체할 수 없나요?
42. `read_admin_token`은 파일 소유자·종류·mode를 확인합니다. symlink, group-readable 파일, 줄바꿈이 있는 token, 너무 긴 token은 어떻게 처리해야 하나요?
43. `valid_admin_authorization`의 constant-time 비교가 완화하는 위험과 완화하지 않는 위험을 구분하고, token이 로그나 예외 메시지에 노출되지 않는 경로를 확인하세요.
44. `publish_policy`는 exact bytes에 서명합니다. operator가 JSON 필드 순서나 공백만 바꿔 재게시하면 signature와 revision 정책은 어떻게 동작해야 하나요?
45. 같은 revision과 동일 document의 재요청은 왜 200 idempotent로 취급할 수 있지만, 같은 revision의 다른 document는 거부해야 하나요?
46. Agent가 잘못된 ETag를 보내 200 전체 envelope를 받는 경우 보안/기능상 결과는 무엇이며, 어떤 검증은 여전히 실행되어야 하나요?
47. Agent가 304 응답을 받았지만 local last-good document가 없다고 주장하는 상황은 어떤 데이터 일관성 위반이며, 왜 조용히 성공 처리하면 안 되나요?
48. policy document가 server DB에 저장된 뒤 signature key가 교체되면 기존 정책의 fetch와 검증은 어떻게 영향을 받나요? key versioning/rotation을 어떻게 설계할까요?
49. Server의 policy row 갱신과 Agent의 last-good/audit 갱신이 서로 다른 DB transaction인 이유는 무엇이며, 네트워크 장애가 발생해도 어떤 불변 조건이 남아야 하나요?
50. 현재 `policy_state`에 저장된 `telemetry_enabled` 값이 실제 event 생성에 영향을 주는지 코드에서 추적하세요. 저장 상태와 runtime 효과가 다를 때 운영 상태 응답은 어떻게 표현해야 하나요?
51. ETag가 문서 SHA-256만 포함할 때 signature key ID나 policy issuer가 바뀌면 캐시 동작은 충분한가요? 더 강한 validator를 만들려면 어떤 식별자를 포함해야 하나요?
52. `If-None-Match` 파서가 중복 헤더를 거부하는 선택과 HTTP 표준의 여러 ETag 문법을 구현하는 선택을 어떤 기준으로 비교하나요?
53. 서버 단일 처리 loop에서 정책 publish와 telemetry ingestion이 동시에 밀릴 때 지연과 backpressure를 어떤 지표로 보이고 어떻게 제한할까요?
54. tenant가 여러 개로 확장되면 현재 `--tenant` 단일 설정과 `policies(tenant_scope PRIMARY KEY)` 구조에서 어떤 권한·쿼리·감사 경계가 달라져야 하나요?
55. 테스트의 operator 인증 거부·게시·재전송·304 확인만으로 operator lifecycle, token rotation, revocation이 검증되었다고 할 수 없는 이유는 무엇인가요?

Owner mastery는 직접 완료한 실습과 근거를 제시하는 방어 답변을 관찰한 뒤에만 평가합니다. 현재 소유자 학습·재현 상태는 **관찰되지 않음**입니다.

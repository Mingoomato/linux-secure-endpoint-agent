# Portfolio review / 포트폴리오 검토 안내

## 문제와 제작 의도

정책으로 제한한 관찰 자료를 인증된 채널로 내구성 있게 전송하기. 이 저장소는 Linux 시스템 호출의 결과와 실패를 관측 가능한 계약으로 연결하는 교육용 구현입니다.

## 핵심 설계

mTLS는 연결 상대를, Ed25519는 정책 bytes의 발급자를 확인합니다. SQLite spool은 ACK된 ID만 제거합니다. 경로는 store별 HMAC으로 가명화하고 정책 watch tree는 별도 FD에서 준비한 뒤 교체합니다. 서버 구현은 loopback 실습 범위입니다.

## 코드 검토 경로

1. [`agent/src/agent.cpp`](../agent/src/agent.cpp)의 CLI 진입점에서 자원 획득과 오류 반환을 찾습니다.
2. [코드 해설](CODE_WALKTHROUGH.md)에서 핵심 함수와 소유권을 따라갑니다.
3. [최신 검증 기록](VALIDATION_CHECKPOINT.md)과 [요구사항 추적표](REQUIREMENTS_TRACEABILITY.md)를 비교합니다.
4. [기술 질문](TECHNICAL_INTERVIEW.md)과 [정답 없는 실습](DEBUGGING_EXERCISES.md)으로 직접 설명·재현합니다.

검토 질문: 서명된 정책에도 scope 검사가 필요한 이유는? ACK를 잃었을 때 중복 처리는? directory rename 뒤 새 FD가 stale watch 이벤트 문제를 어떻게 줄이는가?

## English

**Purpose:** Deliver policy-scoped observations durably over an authenticated channel.

mTLS authenticates peers while Ed25519 authenticates exact policy bytes. The SQLite spool removes only acknowledged IDs. Paths use a store-specific HMAC, and replacement watch trees are prepared on a separate FD before activation. The server is scoped to a loopback lab.

Start with the linked source entry point, follow `CODE_WALKTHROUGH.md`, and compare the dated checkpoint with requirement traceability. Review questions: Why does a signed policy still need scope checks? How are duplicates handled after a lost ACK? How does a fresh FD avoid stale watch events after directory moves?

The five study documents cover subsystem purpose, data/control flow, Linux interfaces, memory/resource lifetime, concurrency, security assumptions, failures and alternatives. Three reproduction exercises remain unsolved. Repository checks and the owner's demonstrated competence are tracked separately; neither AI assistance nor automated test completion establishes personal mastery.

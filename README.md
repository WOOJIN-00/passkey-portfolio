# passkey-portfolio

1번 과제의 자기소개 페이지는 그대로 공개로 두고, 그 아래에 **패스키로만 열리는 "나만의 공간"**을 붙인 8번 과제입니다.
비밀번호는 어디에도 없습니다. 서버는 각 패스키의 **공개키**만 저장합니다.

- 첫 화면(`/`): 누구나 볼 수 있는 공개 소개 페이지 + 잠긴 비공개 영역의 틀
- 비공개 내용: 페이지 소스에 없음. 로그인 뒤 `GET /api/private` 로만 받아 옴
- 비공개 공간에 들어 있는 내용은 모두 만들어 넣은 예시 데이터이고, 실제 개인정보는 없습니다

## 실행

```bash
npm install
npm start            # http://localhost:3000  (패스키는 https 또는 localhost 에서만 동작)
npm run evidence     # 가상 인증기로 확인 30개를 돌리고 ../증거자료/evidence-log.md 에 기록
```

Node 22.5 이상 필요 (`node:sqlite` 사용).

| 환경 변수 | 뜻 | 기본값 |
|---|---|---|
| `RP_ID` | 패스키가 묶일 도메인 (스킴·포트 없이) | `localhost` |
| `ORIGIN` | 브라우저 주소창의 출처 | `http://localhost:3000` |
| `ALLOWED_USERNAMES` | 값이 있으면 이 이름으로만 새 계정 생성 가능 (쉼표 구분) | 비어 있음 = 누구나 |
| `DB_PATH` | SQLite 파일 위치 | `data/app.db` |

## 네 흐름이 지나는 곳

| 흐름 | 브라우저 | 서버 |
|---|---|---|
| 등록 | `public/private.js` `registerPasskey()` | `server.js` `registerOptions()` → 질문 저장 `saveChallenge()` → `registerVerify()` → 질문 소비 `consumeChallenge()` → `verifyRegistrationResponse` → `passkeys` 표에 공개키 저장 |
| 로그인 | `public/private.js` `loginWithPasskey()` | `server.js` `loginOptions()` → `loginVerify()` → `consumeChallenge()` → 저장된 공개키로 `verifyAuthenticationResponse` → `createSession()` |
| 로그아웃 | `logout-button` 클릭 처리 | `server.js` `logout()` : `sessions` 표에서 해시 삭제 + 쿠키 만료 |
| 비공개 자료 조회 | `loadPrivate()` | `server.js` `requireUser()` → `listPrivate()` / `getPrivateItem()` (주인 아니면 403) |
| 패스키 목록·삭제 | `renderPasskeys()`, `deletePasskey()` | `listPasskeys()`, `deletePasskey()` (남의 것 404, 마지막 1개 409) |

## 서버가 저장하는 것

- `users`: 계정 이름, 무작위 사용자 핸들. **비밀번호 칸 없음**
- `passkeys`: credential ID, 이름, **COSE 공개키**, 서명 카운터, 저장 위치 정보(AAGUID, single/multi device), 등록일, 마지막 사용일. **개인키 칸 없음**
- `challenges`: 발급한 일회용 질문, 5분 유효, 확인 시 즉시 삭제
- `sessions`: 세션 토큰의 SHA-256 해시 (원문 저장 안 함), 8시간 유효
- `private_items`: 계정별 비공개 항목

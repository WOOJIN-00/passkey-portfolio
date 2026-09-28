// 증거 기록 스크립트
// 가상 인증기(소프트웨어 패스키)로 서버에 실제 HTTP 요청을 보내고,
// 요청과 응답을 나란히 적은 기록을 ../../증거자료/evidence-log.md 로 남긴다.
//
// 실행:  npm run evidence
//   - 임시 DB 로 서버를 따로 띄우므로 실제 data/app.db 는 건드리지 않는다.
//   - 세션 토큰은 앞 6자만 남기고 가린다.

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PORT = 3199;
const ORIGIN = `http://localhost:${PORT}`;
const RP_ID = 'localhost';
const DB_PATH = path.join(os.tmpdir(), `passkey-evidence-${Date.now()}.db`);
const OUT_PATH = path.join(__dirname, '..', '..', '증거자료', 'evidence-log.md');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

// ─────────────────────────────── 아주 작은 CBOR 인코더 (가상 인증기용)

function cborHead(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
function cbor(value) {
  if (typeof value === 'number') return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  if (typeof value === 'string') { const s = Buffer.from(value, 'utf8'); return Buffer.concat([cborHead(3, s.length), s]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([cborHead(2, value.length), value]);
  if (value instanceof Map) {
    const parts = [cborHead(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return Buffer.concat(parts);
  }
  throw new Error('지원하지 않는 CBOR 값');
}

// ─────────────────────────────── 가상 인증기
// 실제 기기와 똑같이: 열쇠 쌍을 만들고, 개인키는 이 객체 안에만 둔다.

class VirtualAuthenticator {
  constructor(label) {
    this.label = label;
    this.credentials = []; // { id, privateKey, userHandle, signCount }
  }

  create(options, origin = ORIGIN) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credId = crypto.randomBytes(16);
    const coseKey = cbor(new Map([
      [1, 2],                    // kty: EC2
      [3, -7],                   // alg: ES256
      [-1, 1],                   // crv: P-256
      [-2, fromB64u(jwk.x)],
      [-3, fromB64u(jwk.y)],
    ]));
    const counter = Buffer.alloc(4);
    const credIdLen = Buffer.alloc(2); credIdLen.writeUInt16BE(credId.length);
    const authData = Buffer.concat([
      sha256(options.rp.id),
      Buffer.from([0x45]),       // UP + UV + AT
      counter,
      Buffer.alloc(16),          // AAGUID (가상 인증기라 0)
      credIdLen, credId, coseKey,
    ]);
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false,
    }));
    const attestationObject = cbor(new Map([
      ['fmt', 'none'], ['attStmt', new Map()], ['authData', authData],
    ]));
    this.credentials.push({ id: b64u(credId), privateKey, userHandle: options.user.id, signCount: 0 });
    return {
      id: b64u(credId),
      rawId: b64u(credId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        attestationObject: b64u(attestationObject),
        transports: ['internal'],
      },
    };
  }

  // 로그인 질문에 서명한다. overrideId 를 주면 다른 패스키 ID 를 사칭한다(남의 패스키 시험용).
  get(options, { credential = this.credentials[0], overrideId, origin = ORIGIN } = {}) {
    credential.signCount += 1;
    const counter = Buffer.alloc(4); counter.writeUInt32BE(credential.signCount);
    const authenticatorData = Buffer.concat([sha256(options.rpId), Buffer.from([0x05]), counter]);
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false,
    }));
    const signature = crypto.sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), credential.privateKey);
    const id = overrideId || credential.id;
    return {
      id,
      rawId: id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authenticatorData),
        signature: b64u(signature),
        userHandle: overrideId ? undefined : credential.userHandle,
      },
    };
  }
}

// ─────────────────────────────── HTTP + 기록

const log = [];
const out = (line = '') => log.push(line);

function maskToken(value) {
  return String(value).replace(/sid=([A-Za-z0-9_-]{6})[A-Za-z0-9_-]*/g, 'sid=$1…(가림)');
}
function shorten(value, max = 60) {
  if (typeof value === 'string') return value.length > max ? `${value.slice(0, max)}…(${value.length}자)` : value;
  if (Array.isArray(value)) return value.map((v) => shorten(v, max));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shorten(v, max)]));
  }
  return value;
}
function sessionOf(res) {
  const set = res.headers.get('set-cookie');
  const m = set && set.match(/sid=([^;]*)/);
  return m && m[1] ? `sid=${m[1]}` : null;
}

async function call(method, url, { body, cookie, note, record = true, full = false } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(ORIGIN + url, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  if (record) {
    out('```http');
    out(`${method} ${url}${cookie ? `\nCookie: ${maskToken(cookie)}` : ''}`);
    if (body) out(`\n${JSON.stringify(full ? body : shorten(body), null, 2)}`);
    out('```');
    out('```http');
    const setCookie = res.headers.get('set-cookie');
    out(`HTTP ${res.status}${setCookie ? `\nSet-Cookie: ${maskToken(setCookie)}` : ''}`);
    if (typeof data === 'string') out(`\n(본문 ${data.length}자, 아래에서 따로 확인)`);
    else out(`\n${JSON.stringify(shorten(data, 90), null, 2)}`);
    out('```');
    if (note) out(`> ${note}`);
    out();
  }
  return { status: res.status, data, cookie: sessionOf(res), text };
}

function expect(cond, message) {
  if (!cond) throw new Error(`확인 실패: ${message}`);
  results.push(`- [x] ${message}`);
}
const results = [];

// ─────────────────────────────── 시나리오

async function register(auth, { username, passkeyName, cookie }) {
  const opt = await call('POST', '/api/register/options', { body: { username, passkeyName }, cookie, record: false });
  const response = auth.create(opt.data);
  const res = await call('POST', '/api/register/verify', { body: { response }, cookie, record: false });
  return { ...res, options: opt.data, response };
}

async function login(auth, opts = {}) {
  const opt = await call('POST', '/api/login/options', { record: false });
  const response = auth.get(opt.data, opts);
  const res = await call('POST', '/api/login/verify', { body: { response }, record: false });
  return { ...res, options: opt.data, response };
}

async function main() {
  const server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), ORIGIN, RP_ID, DB_PATH, ALLOWED_USERNAMES: '' },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  await new Promise((resolve) => server.stdout.once('data', resolve));

  try {
    await run();
  } finally {
    server.kill();
  }

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(OUT_PATH, log.join('\n'), 'utf8');
  console.log(results.join('\n'));
  console.log(`\n기록 저장: ${OUT_PATH}`);
}

async function run() {
  const alicePhone = new VirtualAuthenticator('alice-기기1');
  const aliceLaptop = new VirtualAuthenticator('alice-기기2');
  const bobDevice = new VirtualAuthenticator('bob-기기');

  out('# 8번 과제 · 패스키 인증 요청/응답 기록');
  out();
  out(`- 생성 시각: ${new Date().toISOString()}`);
  out(`- 대상 서버: ${ORIGIN} (임시 DB, 실제 배포 DB와 분리)`);
  out('- 인증기: 이 스크립트 안의 가상 인증기(P-256 키 쌍을 직접 만들어 서명). 실제 브라우저 패스키와 같은 형식의 요청을 보낸다.');
  out('- 계정 `alice`, `bob` 과 그 안의 비공개 내용은 모두 **만들어 넣은 가짜 데이터**다. 실제 개인정보는 없다.');
  out('- 세션 토큰(`sid`)은 앞 6자만 남기고 가렸다. 긴 base64 값은 앞부분만 적고 길이를 붙였다.');
  out();

  // ── 1. 등록
  out('## 1. 패스키 등록');
  out();
  out('### 1-1. 등록할 때마다 질문(challenge)이 다르다');
  out();
  const regChallenges = [];
  for (let i = 0; i < 3; i++) {
    const r = await call('POST', '/api/register/options', { body: { username: `probe${i}`, passkeyName: 'x' }, record: false });
    regChallenges.push(r.data.challenge);
  }
  out('같은 요청 `POST /api/register/options` 를 세 번 보냈을 때 받은 challenge:');
  out();
  regChallenges.forEach((c, i) => out(`${i + 1}. \`${c}\``));
  out();
  expect(new Set(regChallenges).size === 3, '등록 challenge 3개가 모두 서로 다르다 (T08-C20)');
  const pending = new DatabaseSync(DB_PATH, { readOnly: true })
    .prepare("SELECT challenge, purpose, username, expires_at FROM challenges WHERE purpose='register'").all();
  out('이때 서버 DB `challenges` 표에 보관된 값 (확인할 때까지 서버가 들고 있다):');
  out();
  out('```');
  pending.forEach((p) => out(`${p.challenge}  purpose=${p.purpose}  username=${p.username}  만료=${new Date(p.expires_at).toISOString()}`));
  out('```');
  out();
  expect(regChallenges.every((c) => pending.some((p) => p.challenge === c)), '서버가 발급한 challenge 를 DB에 보관한다 (T08-C19)');

  out('### 1-2. 등록을 중간에 취소하면 아무것도 저장되지 않는다');
  out();
  out('`carol` 이름으로 등록 질문만 받고, 패스키 창에서 취소한 것처럼 확인 요청을 보내지 않았다.');
  out();
  await call('POST', '/api/register/options', { body: { username: 'carol', passkeyName: '취소할 패스키' } });
  const carolRows = new DatabaseSync(DB_PATH, { readOnly: true }).prepare("SELECT COUNT(*) AS n FROM users WHERE username='carol'").get().n;
  out(`취소 뒤 DB: \`SELECT COUNT(*) FROM users WHERE username='carol'\` → **${carolRows}**, 패스키 표에도 carol 의 행 없음. 계정은 등록 확인이 성공한 순간에만 만들어진다. 남아 있는 challenge 는 5분 뒤 만료되고 다음 발급 때 지워진다.`);
  out();
  expect(carolRows === 0, '등록을 취소하면 서버에 계정·패스키가 저장되지 않는다 (T08-C25)');

  out('### 1-3. 실제 등록 요청 본문: 공개키만 가고 개인키는 가지 않는다');
  out();
  const aliceOpt = await call('POST', '/api/register/options', { body: { username: 'alice', passkeyName: 'alice 휴대폰' } });
  const aliceReg = alicePhone.create(aliceOpt.data);
  const aliceVerify = await call('POST', '/api/register/verify', { body: { response: aliceReg } });
  let aliceCookie = aliceVerify.cookie;
  expect(aliceVerify.status === 200, 'alice 첫 패스키 등록 성공');

  const clientData = JSON.parse(fromB64u(aliceReg.response.clientDataJSON).toString());
  out('등록 요청 본문의 필드 전체 목록:');
  out();
  out('```');
  out(`최상위: ${Object.keys(aliceReg).join(', ')}`);
  out(`response: ${Object.keys(aliceReg.response).join(', ')}`);
  out('```');
  out();
  out('`clientDataJSON` 을 풀어 보면 (서버가 보낸 challenge 가 그대로 들어 있다):');
  out();
  out('```json');
  out(JSON.stringify(clientData, null, 2));
  out('```');
  out();
  out('`attestationObject` 는 CBOR 로 `{ fmt: "none", attStmt: {}, authData }` 이고, `authData` 안의 마지막 부분이 COSE 형식 **공개키**(kty=EC2, alg=ES256, x, y)다. 개인키(`d` 값)를 담는 필드는 어디에도 없다.');
  out();
  const bodyText = JSON.stringify(aliceReg);
  const privJwk = alicePhone.credentials[0].privateKey.export({ format: 'jwk' });
  expect(!bodyText.includes(privJwk.d) && !/private|secret|"d"/i.test(bodyText), '등록 요청 본문에 개인키가 없다 (T08-C23)');

  out('### 1-4. 서버에 저장된 값');
  out();
  const stored = new DatabaseSync(DB_PATH, { readOnly: true }).prepare('SELECT * FROM passkeys').get();
  out('DB `passkeys` 표의 행 전체 (이 표에는 비밀번호·개인키 칸이 없다):');
  out();
  out('```');
  for (const [k, v] of Object.entries(stored)) out(`${k.padEnd(12)} ${v}`);
  out('```');
  out();
  const pem = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: alicePhone.credentials[0].privateKey.export({ format: 'jwk' }).x, y: privJwk.y },
    format: 'jwk',
  }).export({ type: 'spki', format: 'pem' });
  out('`public_key` 는 COSE 로 인코딩된 **공개키**다. 같은 키를 표준 PEM 으로 바꾸면:');
  out();
  out('```');
  out(pem.trim());
  out('```');
  out();
  out('이 값은 비밀번호가 아니다. 비밀번호는 알면 그대로 로그인에 쓸 수 있지만, 공개키는 서명이 맞는지 **확인**하는 데만 쓰이고 서명을 **만들** 수 없다. 그래서 이 값이 새어 나가도 누구도 이것으로 로그인할 수 없다. 서명을 만드는 개인키는 등록 요청에 실리지 않았고(1-3), 인증기 안에만 있다.');
  out();
  expect(!('password' in stored) && !('private_key' in stored), '서버 저장 값은 공개키이고 비밀번호·개인키 칸이 없다 (T08-C21, C22)');

  out('로그인한 alice 가 보는 패스키 목록 API (이름·등록일·저장 위치):');
  out();
  await call('GET', '/api/passkeys', { cookie: aliceCookie });

  // ── 2. 로그인
  out('## 2. 패스키 로그인');
  out();
  out('### 2-1. 로그인할 때마다 질문이 다르다');
  out();
  const loginChallenges = [];
  for (let i = 0; i < 3; i++) {
    const r = await call('POST', '/api/login/options', { record: false });
    loginChallenges.push(r.data.challenge);
  }
  loginChallenges.forEach((c, i) => out(`${i + 1}. \`${c}\``));
  out();
  expect(new Set(loginChallenges).size === 3, '로그인 challenge 3개가 모두 서로 다르다 (T08-C27, C28)');

  out('### 2-2. 서명 확인 성공 vs 실패 (나란히)');
  out();
  out('**성공**: 저장된 공개키로 서명을 확인하고 세션 쿠키를 준다.');
  out();
  const okOpt = await call('POST', '/api/login/options');
  const okResponse = alicePhone.get(okOpt.data);
  const ok = await call('POST', '/api/login/verify', { body: { response: okResponse } });
  expect(ok.status === 200 && ok.cookie, '올바른 서명 → 200 + 세션 발급 (T08-C29)');
  aliceCookie = ok.cookie;

  out('**실패**: 새 질문을 받아 서명한 뒤, 서명 한 바이트를 바꿔서 보냈다.');
  out();
  const badOpt = await call('POST', '/api/login/options', { record: false });
  const badResponse = alicePhone.get(badOpt.data);
  const sig = fromB64u(badResponse.response.signature);
  sig[sig.length - 1] ^= 0x01;
  badResponse.response.signature = b64u(sig);
  const bad = await call('POST', '/api/login/verify', { body: { response: badResponse } });
  expect(bad.status === 401 && !bad.cookie, '서명을 1바이트 바꾸면 401, 세션 없음 (T08-C30)');

  out('### 2-3. 이미 쓴 질문을 다시 쓰면 거절된다');
  out();
  out('2-2에서 **성공했던 로그인 응답을 한 글자도 바꾸지 않고** 다시 보냈다 (재전송 공격 흉내).');
  out();
  const replay = await call('POST', '/api/login/verify', { body: { response: okResponse } });
  expect(replay.status === 401 && !replay.cookie, '이미 쓴 challenge 로 다시 로그인하면 401 (T08-C31)');

  out('### 2-4. 로그인 뒤 사람을 알아보는 방법: 서버 세션');
  out();
  out('로그인에 성공하면 서버가 무작위 32바이트 세션 토큰을 `sid` 쿠키(HttpOnly, SameSite=Strict, 배포 시 Secure)로 준다. 서버는 토큰 원문이 아니라 SHA-256 해시만 `sessions` 표에 저장하고, 요청마다 쿠키 → 해시 → 사용자로 찾는다. JWT 같은 자기완결 토큰은 쓰지 않는다.');
  out();
  const sessRow = new DatabaseSync(DB_PATH, { readOnly: true }).prepare('SELECT token_hash, user_id FROM sessions LIMIT 1').get();
  out(`DB에 저장된 모습: \`token_hash=${sessRow.token_hash.slice(0, 12)}…\` (원문 토큰 아님)`);
  out();

  // ── 3. 로그인 없이 / 로그아웃 뒤
  out('## 3. 확인 ① 로그인 없이 열기');
  out();
  // 비공개 자료를 먼저 넣어 둔다
  const aliceItems = [
    { category: 'project', title: '[가짜] 포트폴리오 패스키 붙이기', body: '등록·로그인·삭제 흐름 정리 (예시 데이터)' },
    { category: 'apply', title: '[가짜] 가나다 소프트 백엔드 인턴', body: '마감 10월 말 가정 (예시 데이터)' },
    { category: 'retro', title: '[가짜] 7번 과제 회고', body: '비밀번호 해시보다 패스키가 편했다 (예시 데이터)' },
  ];
  const aliceIds = [];
  for (const item of aliceItems) {
    aliceIds.push((await call('POST', '/api/private/items', { body: item, cookie: aliceCookie, record: false })).data.id);
  }

  out('**성공 (로그인한 alice)**');
  out();
  const withLogin = await call('GET', '/api/private', { cookie: aliceCookie });
  expect(withLogin.status === 200 && withLogin.data.count === 3, '로그인 상태: 비공개 항목 3개를 받는다 (T08-C14)');

  out('**거절 (쿠키 없이 같은 주소)**');
  out();
  const noLogin = await call('GET', '/api/private');
  await call('GET', `/api/private/items/${aliceIds[0]}`);
  expect(noLogin.status === 401, '로그인 없이 비공개 자료 요청 → 401 (T08-C16, C17)');

  out('**로그인하지 않고 받은 첫 화면 HTML 에 비공개 내용이 있는가**');
  out();
  const page = await call('GET', '/', { record: false });
  const scripts = await Promise.all(['/private.js', '/strengths.js'].map((u) => call('GET', u, { record: false })));
  const everything = page.text + scripts.map((s) => s.text).join('');
  const leaked = aliceItems.filter((i) => everything.includes(i.title) || everything.includes(i.body));
  out('```');
  out(`GET /            → HTTP ${page.status}, ${page.text.length}자`);
  out(`GET /private.js  → HTTP ${scripts[0].status}, ${scripts[0].text.length}자`);
  out(`GET /strengths.js→ HTTP ${scripts[1].status}, ${scripts[1].text.length}자`);
  aliceItems.forEach((i) => out(`"${i.title}" 포함 여부: ${everything.includes(i.title) ? '있음' : '없음'}`));
  out('```');
  out();
  expect(page.status === 200 && page.text.includes('송우진') && page.text.includes('나의 강점'), '첫 화면은 로그인 없이 열리는 1번 공개 소개 페이지다 (T08-C10, C11)');
  expect(leaked.length === 0, '로그인 없이 받은 페이지 소스에 비공개 내용이 없다 (T08-C18)');

  out('### 로그아웃한 뒤 같은 세션 값으로 다시 요청');
  out();
  const oldCookie = aliceCookie;
  await call('POST', '/api/logout', { cookie: oldCookie });
  const afterLogout = await call('GET', '/api/private', { cookie: oldCookie, note: '로그아웃 전과 똑같은 sid 값을 보냈지만 서버에서 세션이 지워져 거절된다.' });
  expect(afterLogout.status === 401, '로그아웃 뒤 같은 세션 값 → 401 (T08-C33)');

  // ── 4. 남의 패스키 / 남의 자료
  out('## 4. 확인 ② 남의 패스키로 열기 · 남의 자료 읽기');
  out();
  const bobReg = await register(bobDevice, { username: 'bob', passkeyName: 'bob 노트북' });
  let bobCookie = bobReg.cookie;
  const bobItems = [
    { category: 'project', title: '[가짜] bob 의 사이드 프로젝트', body: 'bob 전용 예시' },
    { category: 'apply', title: '[가짜] 라마바 테크', body: 'bob 전용 예시' },
    { category: 'retro', title: '[가짜] bob 의 주간 회고', body: 'bob 전용 예시' },
  ];
  const bobIds = [];
  for (const item of bobItems) {
    bobIds.push((await call('POST', '/api/private/items', { body: item, cookie: bobCookie, record: false })).data.id);
  }
  aliceCookie = (await login(alicePhone)).cookie;
  out('두 계정 모두 가짜 비공개 항목 3개씩을 넣었다 (alice: 포트폴리오/가나다 소프트/7번 회고, bob: 사이드 프로젝트/라마바 테크/주간 회고).');
  out();
  expect(bobReg.status === 200, '패스키 계정 두 개(alice, bob)에 서로 다른 비공개 내용이 있다 (T08-C36)');

  out('### 4-1. alice 의 개인키로 서명하고 bob 의 패스키 ID 를 달아 로그인 시도');
  out();
  const spoofOpt = await call('POST', '/api/login/options', { record: false });
  const spoof = alicePhone.get(spoofOpt.data, { overrideId: bobDevice.credentials[0].id });
  const spoofRes = await call('POST', '/api/login/verify', {
    body: { response: spoof },
    note: '서버는 bob 패스키의 공개키로 서명을 확인하는데, 서명은 alice 의 개인키로 만든 것이라 맞지 않는다.',
  });
  expect(spoofRes.status === 401, '남의 패스키 ID + 내 서명 → 401');

  out('### 4-2. 이 서버에 등록한 적 없는 패스키로 로그인 시도');
  out();
  const stranger = new VirtualAuthenticator('stranger');
  stranger.create({ rp: { id: RP_ID }, user: { id: 'eA' }, challenge: 'eA' });
  const strangerOpt = await call('POST', '/api/login/options', { record: false });
  const strangerRes = await call('POST', '/api/login/verify', { body: { response: stranger.get(strangerOpt.data) } });
  expect(strangerRes.status === 401, '등록되지 않은 패스키 → 401');

  out('### 4-3. alice → bob 의 비공개 자료 (항목 ID 로 직접 요청)');
  out();
  const bobCountBefore = (await call('GET', '/api/private', { cookie: bobCookie, record: false })).data.count;
  out('**성공 (bob 이 자기 항목을 읽음)**');
  out();
  await call('GET', `/api/private/items/${bobIds[0]}`, { cookie: bobCookie });
  out('**거절 (alice 가 같은 항목을 읽음)**');
  out();
  const a2b = await call('GET', `/api/private/items/${bobIds[0]}`, { cookie: aliceCookie });
  const a2bDel = await call('DELETE', `/api/private/items/${bobIds[1]}`, { cookie: aliceCookie });
  expect(a2b.status === 403 && a2bDel.status === 403, 'alice 가 bob 의 항목 조회·삭제 → 403 (T08-C37)');

  out('### 4-4. bob → alice 의 비공개 자료 (반대 방향)');
  out();
  const aliceCountBefore = (await call('GET', '/api/private', { cookie: aliceCookie, record: false })).data.count;
  const b2a = await call('GET', `/api/private/items/${aliceIds[0]}`, { cookie: bobCookie });
  const b2aDel = await call('DELETE', `/api/private/items/${aliceIds[1]}`, { cookie: bobCookie });
  expect(b2a.status === 403 && b2aDel.status === 403, 'bob 이 alice 의 항목 조회·삭제 → 403 (T08-C38)');

  out('### 4-5. 거절 앞뒤 자료 건수');
  out();
  const bobCountAfter = (await call('GET', '/api/private', { cookie: bobCookie, record: false })).data.count;
  const aliceCountAfter = (await call('GET', '/api/private', { cookie: aliceCookie, record: false })).data.count;
  out('```');
  out(`bob   비공개 항목 수: 거절 전 ${bobCountBefore}개 → 거절 후 ${bobCountAfter}개`);
  out(`alice 비공개 항목 수: 거절 전 ${aliceCountBefore}개 → 거절 후 ${aliceCountAfter}개`);
  out('```');
  out();
  expect(bobCountBefore === bobCountAfter && aliceCountBefore === aliceCountAfter, '거절 앞뒤로 상대편 자료 건수가 같다 (T08-C39)');

  out('### 4-6. 주소·본문에 다른 계정을 적어 보내기');
  out();
  out('주소에 `?user=bob`, `?user_id=...` 을 붙여 alice 세션으로 요청했다. 서버는 이 값을 읽지 않고 세션 주인의 자료만 돌려준다.');
  out();
  const bobUserId = new DatabaseSync(DB_PATH, { readOnly: true }).prepare("SELECT id FROM users WHERE username='bob'").get().id;
  const viaQuery = await call('GET', `/api/private?user=bob&user_id=${bobUserId}`, { cookie: aliceCookie });
  out('본문에 `user_id: bob의 id`, `owner: "bob"` 을 넣어 항목을 만들었다.');
  out();
  const viaBody = await call('POST', '/api/private/items', {
    cookie: aliceCookie,
    body: { category: 'retro', title: '[가짜] 소유자 바꿔치기 시도', body: '', user_id: bobUserId, owner: 'bob' },
  });
  const whoOwns = new DatabaseSync(DB_PATH, { readOnly: true })
    .prepare('SELECT u.username FROM private_items p JOIN users u ON u.id = p.user_id WHERE p.id = ?').get(viaBody.data.id).username;
  out(`DB 확인: 새 항목의 주인 → **${whoOwns}** (bob 이 아님)`);
  out();
  expect(viaQuery.data.owner === 'alice' && viaQuery.data.items.every((i) => i.title.includes('bob') === false) && whoOwns === 'alice',
    '주소·본문에 다른 계정을 적어도 내 자료만 다뤄진다 (T08-C40)');
  // 시험용 항목 정리
  await call('DELETE', `/api/private/items/${viaBody.data.id}`, { cookie: aliceCookie, record: false });

  out('### 4-7. 남의 패스키 삭제 시도');
  out();
  const delOther = await call('DELETE', `/api/passkeys/${bobDevice.credentials[0].id}`, { cookie: aliceCookie });
  expect(delOther.status === 404, 'alice 가 bob 의 패스키 삭제 → 404, bob 패스키는 그대로');

  // ── 5. 이미 쓴 질문 (확인 ③ 요약) – 2-3 에 있음
  out('## 5. 확인 ③ 이미 쓴 질문 재사용');
  out();
  out('2-3 참고. 성공했던 로그인 응답을 그대로 다시 보내면 challenge 가 이미 지워져 있어 401 로 거절된다. 등록 쪽도 같다:');
  out();
  const regReplayOpt = await call('POST', '/api/register/options', { body: { passkeyName: '재사용 시험' }, cookie: bobCookie, record: false });
  const regReplay = bobDevice.create(regReplayOpt.data);
  await call('POST', '/api/register/verify', { body: { response: regReplay }, cookie: bobCookie, record: false });
  const regReplay2 = await call('POST', '/api/register/verify', { body: { response: regReplay }, cookie: bobCookie });
  expect(regReplay2.status === 400, '이미 쓴 등록 challenge 재사용 → 400');

  // ── 6. 패스키 두 개, 하나 삭제
  out('## 6. 확인 ④ 패스키 두 개 등록 → 하나 삭제 → 로그인');
  out();
  out('alice 가 로그인한 채로 두 번째 기기의 패스키를 추가했다.');
  out();
  const addOpt = await call('POST', '/api/register/options', { body: { passkeyName: 'alice 노트북' }, cookie: aliceCookie });
  out(`> 이 질문의 \`excludeCredentials\` 에 이미 등록된 alice 휴대폰 패스키 ID 가 들어 있어, 같은 인증기에 중복 등록되지 않는다: \`${addOpt.data.excludeCredentials.map((c) => c.id).join(', ')}\``);
  out();
  const add = await call('POST', '/api/register/verify', { body: { response: aliceLaptop.create(addOpt.data) }, cookie: aliceCookie });
  expect(add.status === 200, 'alice 두 번째 패스키 등록 성공');
  const list2 = await call('GET', '/api/passkeys', { cookie: aliceCookie });
  expect(list2.data.passkeys.length === 2, '한 계정에 패스키 2개, 목록에 이름·등록일이 보인다 (T08-C42, C43)');

  out('**휴대폰 패스키 삭제 (기기를 잃어버린 상황)**');
  out();
  const del = await call('DELETE', `/api/passkeys/${alicePhone.credentials[0].id}`, { cookie: aliceCookie });
  expect(del.status === 200, '첫 번째 패스키 삭제 성공');

  out('**성공: 남은 노트북 패스키로 로그인**');
  out();
  const lOpt = await call('POST', '/api/login/options', { record: false });
  const withLaptop = await call('POST', '/api/login/verify', { body: { response: aliceLaptop.get(lOpt.data) } });
  expect(withLaptop.status === 200, '남은 패스키로 로그인 성공 (T08-C44)');
  aliceCookie = withLaptop.cookie;

  out('**거절: 지운 휴대폰 패스키로 로그인** (기기 안에는 개인키가 아직 남아 있고 서명도 올바르지만, 서버에 공개키가 없다)');
  out();
  const pOpt = await call('POST', '/api/login/options', { record: false });
  const withPhone = await call('POST', '/api/login/verify', { body: { response: alicePhone.get(pOpt.data) } });
  expect(withPhone.status === 401, '지운 패스키로 로그인 → 401 (T08-C45)');

  out('### 6-1. 패스키가 하나만 남았을 때 그것을 지우려 하면');
  out();
  const lastDel = await call('DELETE', `/api/passkeys/${aliceLaptop.credentials[0].id}`, { cookie: aliceCookie });
  expect(lastDel.status === 409, '마지막 패스키 삭제는 409 로 막힌다 (T08-C46)');
  out('마지막 패스키까지 지우면 이 계정에 들어갈 방법이 영영 사라지므로 서버가 막는다. 화면에서도 패스키가 1개일 때 삭제 버튼이 꺼지고 이유가 안내된다. 단, **서버가 막을 수 있는 건 "스스로 지우는 경우"뿐**이고, 하나 남은 기기를 잃어버리면 복구 수단이 없다 (설명서 ⑥ 참고).');
  out();

  out('## 통과한 확인 목록');
  out();
  results.forEach((r) => out(r));
  out();
}

main().catch((err) => {
  console.error(err);
  console.log(results.join('\n'));
  process.exit(1);
});

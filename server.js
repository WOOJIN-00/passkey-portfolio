// 패스키 포트폴리오 서버
// - 공개 소개 페이지(1번 과제)는 누구나 볼 수 있다.
// - "나만의 공간" 자료는 패스키(WebAuthn)로 로그인한 뒤에만 서버가 내려 준다.
// - 비밀번호는 어디에도 없다. 서버가 저장하는 것은 각 패스키의 "공개키"뿐이다.
//
// 7번 과제처럼 node:http / node:sqlite 내장 모듈을 쓰고,
// 서명 검증(CBOR·COSE 파싱, ECDSA/RSA 검증)만 검증된 라이브러리 @simplewebauthn/server 에 맡긴다.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, randomUUID, createHash, createPublicKey } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const { decodeCredentialPublicKey, cose, isoBase64URL } = require('@simplewebauthn/server/helpers');

const PORT = Number(process.env.PORT || 3000);
// RP_ID 는 도메인 이름(포트·스킴 제외), ORIGIN 은 브라우저 주소창의 스킴+호스트(+포트)
// Render 예: RP_ID=my-app.onrender.com, ORIGIN=https://my-app.onrender.com
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = '송우진 포트폴리오';
const IS_HTTPS = ORIGIN.startsWith('https://');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'app.db');
// 값이 있으면 그 이름으로만 새 계정을 만들 수 있다 (예: "woojin,woojin-sub")
const ALLOWED_USERNAMES = (process.env.ALLOWED_USERNAMES || '')
  .split(',').map((s) => s.trim()).filter(Boolean);

const CHALLENGE_TTL_MS = 5 * 60 * 1000;       // 질문(challenge)은 5분만 유효
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;    // 세션은 8시간
const SESSION_COOKIE = 'sid';

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    webauthn_user_id TEXT NOT NULL UNIQUE,   -- 패스키에 심어 두는 무작위 사용자 핸들(base64url)
    created_at TEXT NOT NULL
  );

  -- 서버가 패스키에 대해 저장하는 전부. 개인키 칸은 없다.
  CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,                     -- credential ID (base64url)
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,                -- COSE 형식 공개키 (base64url)
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '[]',
    device_type TEXT,                        -- singleDevice | multiDevice
    backed_up INTEGER NOT NULL DEFAULT 0,
    aaguid TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT
  );

  -- 서버가 만든 일회용 질문. 확인이 끝나면(성공이든 실패든) 지운다.
  CREATE TABLE IF NOT EXISTS challenges (
    challenge TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,                   -- register | login
    user_id TEXT,                            -- 로그인한 채 패스키를 추가할 때
    username TEXT,                           -- 새 계정을 만들 때
    webauthn_user_id TEXT,                   -- 새 계정에 쓸 사용자 핸들
    passkey_name TEXT,
    expires_at INTEGER NOT NULL
  );

  -- 세션 토큰은 원문 대신 SHA-256 해시만 저장한다.
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS private_items (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL,                  -- project | apply | retro
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
  );
`);

// 자주 보이는 인증기 AAGUID → 사람이 읽을 이름 (패스키가 어디에 저장됐는지 보여 주기 위함)
const KNOWN_AAGUIDS = {
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google 비밀번호 관리자',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud 키체인',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud 키체인 (관리형)',
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  '00000000-0000-0000-0000-000000000000': '알 수 없음 (인증기가 밝히지 않음)',
};

function describeStorage(row) {
  const known = KNOWN_AAGUIDS[row.aaguid];
  const synced = row.device_type === 'multiDevice';
  const kind = synced
    ? '동기화되는 패스키 (계정 비밀번호 관리자에 보관)'
    : '기기에 묶인 패스키 (이 기기·보안 키 안에만 있음)';
  return known ? `${known} · ${kind}` : kind;
}

// ─────────────────────────────── 공통 도우미

const nowIso = () => new Date().toISOString();
const sha256 = (s) => createHash('sha256').update(s).digest('hex');

function sendJson(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 100 * 1024) throw Object.assign(new Error('요청이 너무 큽니다.'), { status: 413 });
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('JSON 형식이 아닙니다.'), { status: 400 });
  }
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function sessionCookie(token, maxAgeSec) {
  return [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSec}`,
    IS_HTTPS ? 'Secure' : '',
  ].filter(Boolean).join('; ');
}

// ─────────────────────────────── 세션

function createSession(userId) {
  const token = randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(sha256(token), userId, nowIso(), Date.now() + SESSION_TTL_MS);
  return sessionCookie(token, SESSION_TTL_MS / 1000);
}

// 쿠키의 세션 토큰 → 사용자. 없거나 만료·로그아웃된 토큰이면 null
function currentUser(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.id, u.username, s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?`).get(sha256(token));
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return null;
  }
  return { id: row.id, username: row.username };
}

function requireUser(req, res) {
  const user = currentUser(req);
  if (!user) sendJson(res, 401, { error: '패스키로 로그인해야 볼 수 있습니다.' });
  return user;
}

// ─────────────────────────────── 일회용 질문(challenge)

function saveChallenge({ challenge, purpose, userId = null, username = null, webauthnUserId = null, passkeyName = null }) {
  db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(Date.now());
  db.prepare(`INSERT INTO challenges (challenge, purpose, user_id, username, webauthn_user_id, passkey_name, expires_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(challenge, purpose, userId, username, webauthnUserId, passkeyName, Date.now() + CHALLENGE_TTL_MS);
}

// 브라우저가 서명한 clientDataJSON 안의 challenge 를 꺼내, 서버가 보관 중인 것인지 확인하고 즉시 지운다.
// 한 번 꺼낸 질문은 검증 결과와 상관없이 사라지므로 같은 응답을 다시 보내면 거절된다.
function consumeChallenge(response, purpose) {
  let challenge;
  try {
    const clientData = JSON.parse(isoBase64URL.toUTF8String(response.response.clientDataJSON));
    challenge = clientData.challenge;
  } catch {
    return { error: 'clientDataJSON 을 읽을 수 없습니다.' };
  }
  const row = db.prepare('SELECT * FROM challenges WHERE challenge = ? AND purpose = ?').get(challenge, purpose);
  if (!row) return { error: '서버가 발급하지 않았거나 이미 사용된 질문(challenge)입니다.' };
  db.prepare('DELETE FROM challenges WHERE challenge = ?').run(challenge);
  if (row.expires_at < Date.now()) return { error: '질문(challenge)의 유효 시간 5분이 지났습니다.' };
  return { row };
}

// ─────────────────────────────── 라우트: 등록

async function registerOptions(req, res) {
  const body = await readJson(req);
  const me = currentUser(req);
  const passkeyName = String(body.passkeyName || '').trim().slice(0, 40) || '이름 없는 패스키';
  // 저장 위치 선택: localDevice(이 기기·Windows Hello·Chrome), remoteDevice(휴대폰 QR), securityKey(USB 보안 키)
  // 고르지 않으면 브라우저가 쓸 수 있는 것을 모두 보여 준다
  const authenticatorType = ['localDevice', 'remoteDevice', 'securityKey'].includes(body.authenticatorType)
    ? body.authenticatorType
    : undefined;

  let user;
  if (me) {
    // 로그인 상태 → 내 계정에 패스키를 하나 더 추가
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(me.id);
  } else {
    // 로그아웃 상태 → 새 계정. 계정은 등록 확인이 끝난 뒤에야 DB에 만들어진다(취소 시 아무것도 남지 않음).
    const username = String(body.username || '').trim();
    if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
      return sendJson(res, 400, { error: '이름은 영문·숫자·_- 3~20자로 적어 주세요.' });
    }
    if (ALLOWED_USERNAMES.length && !ALLOWED_USERNAMES.includes(username)) {
      return sendJson(res, 403, { error: '이 사이트는 정해진 계정만 새로 만들 수 있습니다.' });
    }
    if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
      return sendJson(res, 409, { error: '이미 있는 이름입니다. 그 계정의 패스키로 로그인하세요.' });
    }
    user = { id: null, username, webauthn_user_id: isoBase64URL.fromBuffer(randomBytes(32)) };
  }

  const existing = user.id
    ? db.prepare('SELECT id, transports FROM passkeys WHERE user_id = ?').all(user.id)
    : [];

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.username,
    userDisplayName: user.username,
    userID: isoBase64URL.toBuffer(user.webauthn_user_id),
    attestationType: 'none',
    // 같은 인증기에 같은 계정의 패스키가 두 번 생기지 않도록, 이미 등록된 것은 제외하라고 알려 준다
    excludeCredentials: existing.map((p) => ({ id: p.id, transports: JSON.parse(p.transports) })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    preferredAuthenticatorType: authenticatorType,
  });

  saveChallenge({
    challenge: options.challenge,
    purpose: 'register',
    userId: user.id,
    username: user.id ? null : user.username,
    webauthnUserId: user.id ? null : user.webauthn_user_id,
    passkeyName,
  });
  sendJson(res, 200, options);
}

async function registerVerify(req, res) {
  const body = await readJson(req);
  const response = body.response;
  if (!response || !response.response) return sendJson(res, 400, { error: '등록 응답이 없습니다.' });

  const { row, error } = consumeChallenge(response, 'register');
  if (error) return sendJson(res, 400, { error });

  // 로그인 상태에서 받은 질문이면, 확인하는 지금도 같은 사람이어야 한다
  const me = currentUser(req);
  if (row.user_id && (!me || me.id !== row.user_id)) {
    return sendJson(res, 403, { error: '패스키 추가를 시작한 계정과 지금 로그인한 계정이 다릅니다.' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: row.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });
  } catch (err) {
    return sendJson(res, 400, { error: `등록 검증 실패: ${err.message}` });
  }
  if (!verification.verified) return sendJson(res, 400, { error: '등록 검증 실패' });

  const { credential, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;
  if (db.prepare('SELECT 1 FROM passkeys WHERE id = ?').get(credential.id)) {
    return sendJson(res, 409, { error: '이미 등록된 패스키입니다.' });
  }

  let userId = row.user_id;
  let setCookie;
  if (!userId) {
    const username = row.username;
    if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
      return sendJson(res, 409, { error: '그 사이 같은 이름의 계정이 만들어졌습니다.' });
    }
    userId = randomUUID();
    db.prepare('INSERT INTO users (id, username, webauthn_user_id, created_at) VALUES (?, ?, ?, ?)')
      .run(userId, username, row.webauthn_user_id, nowIso());
    setCookie = createSession(userId); // 첫 패스키를 만든 사람은 바로 들어간 상태가 된다
  }

  db.prepare(`INSERT INTO passkeys
      (id, user_id, name, public_key, counter, transports, device_type, backed_up, aaguid, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(
      credential.id,
      userId,
      row.passkey_name,
      isoBase64URL.fromBuffer(credential.publicKey),
      credential.counter,
      JSON.stringify(credential.transports || []),
      credentialDeviceType,
      credentialBackedUp ? 1 : 0,
      aaguid,
      nowIso(),
    );

  sendJson(res, 200, { verified: true, passkeyId: credential.id },
    setCookie ? { 'Set-Cookie': setCookie } : {});
}

// ─────────────────────────────── 라우트: 로그인 / 로그아웃

async function loginOptions(req, res) {
  // 사용자 이름을 묻지 않는다. 기기에 저장된 패스키(discoverable credential)를 브라우저가 골라 준다.
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'preferred',
  });
  saveChallenge({ challenge: options.challenge, purpose: 'login' });
  sendJson(res, 200, options);
}

async function loginVerify(req, res) {
  const body = await readJson(req);
  const response = body.response;
  if (!response || !response.response) return sendJson(res, 400, { error: '로그인 응답이 없습니다.' });

  const { row, error } = consumeChallenge(response, 'login');
  if (error) return sendJson(res, 401, { error });

  const passkey = db.prepare('SELECT * FROM passkeys WHERE id = ?').get(String(response.id));
  if (!passkey) return sendJson(res, 401, { error: '이 서버에 등록되지 않았거나 삭제된 패스키입니다.' });

  let verification;
  try {
    // 저장해 둔 공개키로 서명을 확인한다. 여기서 통과하지 못하면 세션을 주지 않는다.
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: row.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: passkey.id,
        publicKey: isoBase64URL.toBuffer(passkey.public_key),
        counter: passkey.counter,
        transports: JSON.parse(passkey.transports),
      },
      requireUserVerification: false,
    });
  } catch (err) {
    return sendJson(res, 401, { error: `서명 확인 실패: ${err.message}` });
  }
  if (!verification.verified) return sendJson(res, 401, { error: '서명 확인 실패' });

  // userHandle 이 오면 패스키 주인과 일치하는지도 본다
  const owner = db.prepare('SELECT * FROM users WHERE id = ?').get(passkey.user_id);
  if (response.response.userHandle && response.response.userHandle !== owner.webauthn_user_id) {
    return sendJson(res, 401, { error: '패스키의 사용자 정보가 일치하지 않습니다.' });
  }

  db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?')
    .run(verification.authenticationInfo.newCounter, nowIso(), passkey.id);

  sendJson(res, 200, { verified: true, username: owner.username },
    { 'Set-Cookie': createSession(owner.id) });
}

function logout(req, res) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  sendJson(res, 200, { loggedOut: true }, { 'Set-Cookie': sessionCookie('', 0) });
}

function me(req, res) {
  const user = requireUser(req, res);
  if (!user) return;
  sendJson(res, 200, { username: user.username });
}

// ─────────────────────────────── 라우트: 패스키 목록 / 삭제

function publicKeyInfo(publicKeyB64) {
  // 저장된 COSE 공개키를 사람이 볼 수 있는 JWK/PEM 으로 바꿔 "이건 공개키다"를 보여 준다
  try {
    const coseKey = decodeCredentialPublicKey(isoBase64URL.toBuffer(publicKeyB64));
    const kty = coseKey.get(cose.COSEKEYS.kty);
    let jwk;
    if (kty === cose.COSEKTY.EC2) {
      jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: isoBase64URL.fromBuffer(coseKey.get(cose.COSEKEYS.x)),
        y: isoBase64URL.fromBuffer(coseKey.get(cose.COSEKEYS.y)),
      };
    } else if (kty === cose.COSEKTY.RSA) {
      jwk = {
        kty: 'RSA',
        n: isoBase64URL.fromBuffer(coseKey.get(cose.COSEKEYS.n)),
        e: isoBase64URL.fromBuffer(coseKey.get(cose.COSEKEYS.e)),
      };
    } else if (kty === cose.COSEKTY.OKP) {
      jwk = { kty: 'OKP', crv: 'Ed25519', x: isoBase64URL.fromBuffer(coseKey.get(cose.COSEKEYS.x)) };
    }
    const pem = jwk ? createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' }) : null;
    return { algorithm: coseKey.get(cose.COSEKEYS.alg), jwk, pem };
  } catch {
    return null;
  }
}

function listPasskeys(req, res) {
  const user = requireUser(req, res);
  if (!user) return;
  const rows = db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at').all(user.id);
  sendJson(res, 200, {
    passkeys: rows.map((p) => ({
      id: p.id,
      name: p.name,
      createdAt: p.created_at,
      lastUsedAt: p.last_used_at,
      storage: describeStorage(p),
      deviceType: p.device_type,
      aaguid: p.aaguid,
      storedPublicKey: p.public_key,
      publicKey: publicKeyInfo(p.public_key),
    })),
  });
}

function deletePasskey(req, res, passkeyId) {
  const user = requireUser(req, res);
  if (!user) return;
  const passkey = db.prepare('SELECT * FROM passkeys WHERE id = ?').get(passkeyId);
  // 남의 패스키이면 존재 여부와 상관없이 같은 답을 준다
  if (!passkey || passkey.user_id !== user.id) {
    return sendJson(res, 404, { error: '내 계정에 그런 패스키가 없습니다.' });
  }
  const count = db.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?').get(user.id).n;
  if (count <= 1) {
    return sendJson(res, 409, {
      error: '마지막 남은 패스키는 지울 수 없습니다. 지우면 이 계정에 다시 들어갈 방법이 없어집니다. 먼저 다른 패스키를 하나 더 등록하세요.',
    });
  }
  db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(passkeyId, user.id);
  sendJson(res, 200, { deleted: true, remaining: count - 1 });
}

// ─────────────────────────────── 라우트: 비공개 자료

const CATEGORIES = { project: '준비 중인 프로젝트 메모', apply: '지원하려는 곳', retro: '나의 회고' };

function listPrivate(req, res) {
  const user = requireUser(req, res);
  if (!user) return;
  // 주소나 본문에 다른 계정(?user=...)을 적어 보내도 무시한다. 조회 대상은 언제나 세션의 주인이다.
  const items = db.prepare(
    'SELECT id, category, title, body, created_at AS createdAt FROM private_items WHERE user_id = ? ORDER BY created_at',
  ).all(user.id);
  sendJson(res, 200, { owner: user.username, count: items.length, items });
}

function getPrivateItem(req, res, itemId) {
  const user = requireUser(req, res);
  if (!user) return;
  const item = db.prepare('SELECT * FROM private_items WHERE id = ?').get(itemId);
  if (!item) return sendJson(res, 404, { error: '없는 항목입니다.' });
  if (item.user_id !== user.id) return sendJson(res, 403, { error: '다른 계정의 비공개 자료는 볼 수 없습니다.' });
  sendJson(res, 200, {
    id: item.id, category: item.category, title: item.title, body: item.body, createdAt: item.created_at,
  });
}

async function createPrivateItem(req, res) {
  const user = requireUser(req, res);
  if (!user) return;
  const body = await readJson(req);
  const category = String(body.category || '');
  const title = String(body.title || '').trim().slice(0, 100);
  const text = String(body.body || '').trim().slice(0, 2000);
  if (!CATEGORIES[category]) return sendJson(res, 400, { error: '분류가 올바르지 않습니다.' });
  if (!title) return sendJson(res, 400, { error: '제목을 적어 주세요.' });
  const id = randomUUID();
  // user_id 는 본문에서 받지 않고 세션에서만 가져온다
  db.prepare('INSERT INTO private_items (id, user_id, category, title, body, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, user.id, category, title, text, nowIso());
  sendJson(res, 201, { id });
}

function deletePrivateItem(req, res, itemId) {
  const user = requireUser(req, res);
  if (!user) return;
  const item = db.prepare('SELECT user_id FROM private_items WHERE id = ?').get(itemId);
  if (!item) return sendJson(res, 404, { error: '없는 항목입니다.' });
  if (item.user_id !== user.id) return sendJson(res, 403, { error: '다른 계정의 비공개 자료는 지울 수 없습니다.' });
  db.prepare('DELETE FROM private_items WHERE id = ? AND user_id = ?').run(itemId, user.id);
  sendJson(res, 200, { deleted: true });
}

// ─────────────────────────────── 정적 파일

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  const filePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('찾을 수 없습니다.');
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    });
    res.end(data);
  });
}

// ─────────────────────────────── 라우터

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://placeholder');
  const { pathname } = url;
  const m = req.method;
  try {
    if (m === 'POST' && pathname === '/api/register/options') return await registerOptions(req, res);
    if (m === 'POST' && pathname === '/api/register/verify') return await registerVerify(req, res);
    if (m === 'POST' && pathname === '/api/login/options') return await loginOptions(req, res);
    if (m === 'POST' && pathname === '/api/login/verify') return await loginVerify(req, res);
    if (m === 'POST' && pathname === '/api/logout') return logout(req, res);
    if (m === 'GET' && pathname === '/api/me') return me(req, res);
    if (m === 'GET' && pathname === '/api/passkeys') return listPasskeys(req, res);

    let match = pathname.match(/^\/api\/passkeys\/([A-Za-z0-9_-]+)$/);
    if (m === 'DELETE' && match) return deletePasskey(req, res, match[1]);

    if (m === 'GET' && pathname === '/api/private') return listPrivate(req, res);
    if (m === 'POST' && pathname === '/api/private/items') return await createPrivateItem(req, res);
    match = pathname.match(/^\/api\/private\/items\/([0-9a-f-]{36})$/);
    if (m === 'GET' && match) return getPrivateItem(req, res, match[1]);
    if (m === 'DELETE' && match) return deletePrivateItem(req, res, match[1]);

    if (pathname.startsWith('/api/')) return sendJson(res, 404, { error: '없는 API 입니다.' });
    if (m === 'GET' || m === 'HEAD') return serveStatic(req, res, pathname);
    res.writeHead(405);
    res.end();
  } catch (err) {
    if (!res.headersSent) sendJson(res, err.status || 500, { error: err.status ? err.message : '서버 오류' });
    if (!err.status) console.error(err);
  }
});

server.listen(PORT, () => {
  console.log(`패스키 포트폴리오 서버: ${ORIGIN} (RP_ID=${RP_ID}, DB=${DB_PATH})`);
});

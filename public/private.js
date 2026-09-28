// 나만의 공간: 패스키 등록 / 로그인 / 로그아웃 / 비공개 자료 조회
// 비공개 내용은 이 파일에도, index.html 에도 없다. 로그인 뒤 서버에서 받아 화면에 넣는다.

(function () {

  const $ = (id) => document.getElementById(id);

  const CATEGORY_LABELS = {
    project: "준비 중인 프로젝트 메모",
    apply: "지원하려는 곳",
    retro: "나의 회고",
  };


  /* ---------- base64url <-> ArrayBuffer ---------- */

  function toBuffer(base64url) {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "===".slice((base64.length + 3) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function toBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }


  /* ---------- 서버 요청 ---------- */

  async function api(method, url, body) {
    const res = await fetch(url, {
      method,
      credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      // JSON 오류가 아니면 이 서버가 아닌 곳(예: VS Code Live Server)에서 페이지를 연 것이다
      const fallback = data.error
        ? data.error
        : `요청 실패 (${res.status}). 패스키 서버가 응답하지 않았습니다. ` +
          "Live Server 가 아니라 npm start 로 띄운 주소(http://localhost:3000)에서 열어 주세요.";
      const err = new Error(fallback);
      err.status = res.status;
      throw err;
    }
    return data;
  }


  /* ---------- 화면 안내 ---------- */

  function showMessage(text, kind) {
    const box = $("message");
    box.textContent = text;
    box.className = "message" + (kind ? " " + kind : "");
    box.hidden = false;
  }

  function clearMessage() {
    $("message").hidden = true;
  }

  // 패스키 창에서 생긴 오류를 사람이 읽을 말로 바꾼다
  function explainWebAuthnError(err) {
    if (err.name === "NotAllowedError") {
      return "패스키 창이 취소되었거나 시간이 지났습니다. 서버에는 아무것도 저장되지 않았습니다. 다시 시도해 주세요.";
    }
    if (err.name === "InvalidStateError") {
      return "이 기기(또는 비밀번호 관리자)에는 이미 이 계정의 패스키가 있습니다. 휴대폰·다른 브라우저·보안 키로 등록해 보세요.";
    }
    if (err.name === "SecurityError") {
      return "보안 오류: https 주소(또는 localhost)에서만 패스키를 쓸 수 있습니다.";
    }
    if (err.name === "NotSupportedError") {
      return "이 브라우저나 기기는 패스키를 지원하지 않습니다.";
    }
    return err.message || String(err);
  }

  function supportsPasskeys() {
    return window.PublicKeyCredential && navigator.credentials && navigator.credentials.create;
  }


  /* ---------- 등록: 서버 질문 → 기기가 열쇠 쌍 생성 → 공개키만 서버로 ---------- */

  async function registerPasskey({ username, passkeyName, authenticatorType }) {
    const options = await api("POST", "/api/register/options", { username, passkeyName, authenticatorType });

    const publicKey = {
      ...options,
      challenge: toBuffer(options.challenge),
      user: { ...options.user, id: toBuffer(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: toBuffer(c.id) })),
    };

    const credential = await navigator.credentials.create({ publicKey });

    // 서버로 보내는 것: 공개키가 들어 있는 attestationObject, 서명된 clientDataJSON.
    // 개인키는 기기 밖으로 나오지 않으므로 보낼 방법 자체가 없다.
    const response = {
      id: credential.id,
      rawId: toBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: toBase64url(credential.response.clientDataJSON),
        attestationObject: toBase64url(credential.response.attestationObject),
        transports: credential.response.getTransports ? credential.response.getTransports() : [],
      },
    };

    return api("POST", "/api/register/verify", { response });
  }


  /* ---------- 로그인: 서버 질문 → 기기가 개인키로 서명 → 서버가 공개키로 확인 ---------- */

  async function loginWithPasskey() {
    const options = await api("POST", "/api/login/options");

    const publicKey = {
      ...options,
      challenge: toBuffer(options.challenge),
      allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: toBuffer(c.id) })),
    };

    const assertion = await navigator.credentials.get({ publicKey });

    const response = {
      id: assertion.id,
      rawId: toBase64url(assertion.rawId),
      type: assertion.type,
      authenticatorAttachment: assertion.authenticatorAttachment,
      clientExtensionResults: assertion.getClientExtensionResults(),
      response: {
        clientDataJSON: toBase64url(assertion.response.clientDataJSON),
        authenticatorData: toBase64url(assertion.response.authenticatorData),
        signature: toBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? toBase64url(assertion.response.userHandle) : undefined,
      },
    };

    return api("POST", "/api/login/verify", { response });
  }


  /* ---------- 화면 그리기 ---------- */

  function el(tag, props, children) {
    const node = document.createElement(tag);
    Object.assign(node, props || {});
    for (const child of children || []) node.append(child);
    return node;
  }

  function formatDate(iso) {
    if (!iso) return "없음";
    return new Date(iso).toLocaleString("ko-KR", { dateStyle: "medium", timeStyle: "short" });
  }

  function setLocked(locked) {
    $("locked-view").hidden = !locked;
    $("unlocked-view").hidden = locked;
    const state = $("lock-state");
    state.textContent = locked ? "잠김" : "열림";
    state.classList.toggle("open", !locked);
    if (locked) {
      // 잠글 때는 화면에 남아 있던 비공개 내용도 지운다
      $("item-columns").replaceChildren();
      $("passkey-list").replaceChildren();
      $("who").textContent = "";
    }
  }

  function renderItems(data) {
    $("item-count").textContent = `(${data.count}개)`;
    const columns = Object.entries(CATEGORY_LABELS).map(([key, label]) => {
      const items = data.items.filter((item) => item.category === key);
      const list = el("ul", {}, items.map((item) =>
        el("li", { className: "item-card" }, [
          el("strong", { textContent: item.title }),
          el("p", { textContent: item.body }),
          el("button", {
            type: "button",
            className: "btn btn-danger",
            textContent: "삭제",
            onclick: () => deleteItem(item),
          }),
        ]),
      ));
      if (!items.length) list.append(el("li", { className: "empty", textContent: "아직 없음" }));
      return el("div", { className: "item-column" }, [el("h4", { textContent: label }), list]);
    });
    $("item-columns").replaceChildren(...columns);
  }

  function renderPasskeys(passkeys) {
    $("passkey-count").textContent = `(${passkeys.length}개)`;
    $("passkey-list").replaceChildren(...passkeys.map((p) => {
      const deleteButton = el("button", {
        type: "button",
        className: "btn btn-danger",
        textContent: "이 패스키 삭제",
        onclick: () => deletePasskey(p),
      });
      if (passkeys.length <= 1) {
        deleteButton.disabled = true;
        deleteButton.title = "마지막 남은 패스키는 지울 수 없습니다.";
      }
      const publicKeyText = p.publicKey
        ? `알고리즘(COSE alg): ${p.publicKey.algorithm}\n\nJWK:\n${JSON.stringify(p.publicKey.jwk, null, 2)}\n\n${p.publicKey.pem}`
        : p.storedPublicKey;
      return el("li", { className: "passkey-item" }, [
        el("div", { className: "passkey-top" }, [el("strong", { textContent: p.name }), deleteButton]),
        el("ul", { className: "passkey-meta" }, [
          el("li", { textContent: `등록한 날: ${formatDate(p.createdAt)}` }),
          el("li", { textContent: `마지막 사용: ${formatDate(p.lastUsedAt)}` }),
          el("li", { textContent: `저장 위치: ${p.storage}` }),
          el("li", { textContent: `패스키 ID: ${p.id.slice(0, 16)}…` }),
        ]),
        el("details", {}, [
          el("summary", { textContent: "서버에 저장된 값 보기 (공개키)" }),
          el("p", {
            textContent: "서버가 이 패스키에 대해 가진 것은 아래 공개키뿐입니다. 공개키는 서명을 확인하는 데만 쓰이고, 이것으로는 서명을 만들 수 없습니다.",
          }),
          el("pre", { textContent: `저장된 원본(COSE, base64url):\n${p.storedPublicKey}\n\n${publicKeyText}` }),
        ]),
      ]);
    }));
  }

  async function loadPrivate() {
    const [me, privateData, passkeyData] = await Promise.all([
      api("GET", "/api/me"),
      api("GET", "/api/private"),
      api("GET", "/api/passkeys"),
    ]);
    $("who").textContent = me.username;
    renderItems(privateData);
    renderPasskeys(passkeyData.passkeys);
    setLocked(false);
  }

  async function refresh() {
    try {
      await loadPrivate();
    } catch (err) {
      if (err.status === 401) setLocked(true);
      else showMessage(err.message, "error");
    }
  }


  /* ---------- 버튼 동작 ---------- */

  async function withButton(button, task) {
    button.disabled = true;
    clearMessage();
    try {
      await task();
    } finally {
      button.disabled = false;
    }
  }

  $("login-button").addEventListener("click", (event) => {
    withButton(event.currentTarget, async () => {
      if (!supportsPasskeys()) return showMessage("이 브라우저는 패스키를 지원하지 않습니다.", "error");
      try {
        const result = await loginWithPasskey();
        await loadPrivate();
        showMessage(`${result.username} 계정으로 들어왔습니다.`, "ok");
      } catch (err) {
        showMessage(explainWebAuthnError(err), "error");
      }
    });
  });

  $("register-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    withButton(button, async () => {
      if (!supportsPasskeys()) return showMessage("이 브라우저는 패스키를 지원하지 않습니다.", "error");
      try {
        await registerPasskey({
          username: $("register-username").value.trim(),
          passkeyName: $("register-passkey-name").value.trim(),
          authenticatorType: $("register-authenticator").value,
        });
        event.target.reset();
        await loadPrivate();
        showMessage("패스키를 만들고 들어왔습니다. 서버에는 공개키만 저장되었습니다.", "ok");
      } catch (err) {
        showMessage(explainWebAuthnError(err), "error");
      }
    });
  });

  $("add-passkey-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    withButton(button, async () => {
      try {
        await registerPasskey({
          passkeyName: $("add-passkey-name").value.trim(),
          authenticatorType: $("add-passkey-authenticator").value,
        });
        event.target.reset();
        await loadPrivate();
        showMessage("패스키를 하나 더 등록했습니다.", "ok");
      } catch (err) {
        showMessage(explainWebAuthnError(err), "error");
      }
    });
  });

  $("logout-button").addEventListener("click", (event) => {
    withButton(event.currentTarget, async () => {
      await api("POST", "/api/logout").catch(() => {});
      setLocked(true);
      showMessage("로그아웃했습니다. 비공개 내용은 화면에서 지웠습니다.", "ok");
    });
  });

  $("item-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector("button");
    withButton(button, async () => {
      try {
        await api("POST", "/api/private/items", {
          category: $("item-category").value,
          title: $("item-title").value.trim(),
          body: $("item-body").value.trim(),
        });
        $("item-title").value = "";
        $("item-body").value = "";
        await loadPrivate();
      } catch (err) {
        if (err.status === 401) setLocked(true);
        showMessage(err.message, "error");
      }
    });
  });

  async function deleteItem(item) {
    if (!confirm(`"${item.title}" 항목을 지울까요?`)) return;
    try {
      await api("DELETE", `/api/private/items/${item.id}`);
      await loadPrivate();
    } catch (err) {
      if (err.status === 401) setLocked(true);
      showMessage(err.message, "error");
    }
  }

  async function deletePasskey(passkey) {
    if (!confirm(`"${passkey.name}" 패스키를 지울까요? 지운 패스키로는 더 이상 들어올 수 없습니다.`)) return;
    try {
      const result = await api("DELETE", `/api/passkeys/${passkey.id}`);
      await loadPrivate();
      showMessage(
        `"${passkey.name}" 패스키를 지웠습니다. 남은 패스키 ${result.remaining}개. ` +
        "기기의 비밀번호 관리자에는 아직 남아 있을 수 있으니 거기서도 지워 두세요.",
        "ok",
      );
    } catch (err) {
      if (err.status === 401) setLocked(true);
      showMessage(err.message, "error");
    }
  }

  // 이 기기(Windows Hello 등)에 패스키를 저장할 수 있는지 미리 물어보고, 안 되면 설정 방법을 보여 준다
  async function checkPlatformAuthenticator() {
    if (!supportsPasskeys()) return;
    let available = false;
    try {
      available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      available = false;
    }
    $("platform-notice").hidden = available;
    // 이 기기에 저장할 수 있으면 기본 선택을 "이 기기"로 둔다
    if (available) {
      for (const select of document.querySelectorAll(".authenticator-select")) select.value = "localDevice";
    }
  }

  setLocked(true);
  refresh();
  checkPlatformAuthenticator();

})();

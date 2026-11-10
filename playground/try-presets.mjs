// /try 정책 실험실 프리셋. 각 프리셋 = (정책, 전달 방식, HTML) 한 벌.
// mode: header | report-only | meta | two-headers | enforce+report
const mark = (label) => `<script src="/static/try-mark.js" data-label="${label}"></script>`;

export const TRY_PRESETS = [
  {
    id: "basic",
    title: "기본 — script-src 'self'",
    mode: "header",
    policy: "script-src 'self'",
    html: `${mark("같은 origin 외부 script")}
<script>document.body.append("✅ 인라인 script 실행됨")</script>
<img src="x" onerror="document.body.append('✅ 인라인 핸들러 실행됨')">`,
  },
  {
    id: "quotes",
    title: "따옴표 실수 — script-src self",
    mode: "header",
    policy: "script-src self",
    html: mark("같은 origin 외부 script"),
  },
  {
    id: "inline-kinds",
    title: "무엇이 '인라인'인가 — 위반 지시어 비교",
    mode: "header",
    policy: "script-src 'self'",
    html: `<script>document.body.append("인라인 script")</script>
<img src="x" onerror="document.body.append('인라인 핸들러')">
<a id="js-link" href="javascript:document.body.append('javascript: URL')">javascript: 링크 (클릭)</a>
<script src="/static/try-eval.js"></script>`,
  },
  {
    id: "default-fallback",
    title: "default-src 폴백 — 덮는 것과 안 덮는 것",
    mode: "header",
    policy: "default-src 'self'",
    html: `<img src="http://localhost:3001/img/ok.svg" width="40" alt="CDN 이미지">
<script>document.body.append("인라인 script")</script>
<base href="http://localhost:4000/">
<a href="profile">내 프로필 (상대 링크 → base 를 따라감)</a>
<form action="http://localhost:4000/phish" method="post"><input name="password" value="hunter2"><button>외부로 form 제출</button></form>`,
  },
  {
    id: "wildcard-data",
    title: "* 와일드카드는 data:/blob: 을 포함하지 않는다",
    mode: "header",
    policy: "img-src *",
    html: `<img src="http://localhost:4000/img/ok.svg" width="40" alt="다른 origin 이미지">
<img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='40' height='40'%3E%3Crect width='40' height='40' fill='%2329a36a'/%3E%3C/svg%3E" alt="data: 이미지">`,
  },
  {
    id: "host-path",
    title: "호스트 · 서브도메인 · 경로 매칭",
    mode: "header",
    policy: "img-src http://*.localhost:3001 http://localhost:4000/img/",
    html: `<img src="http://cdn.localhost:3001/img/ok.svg" width="40" alt="cdn.localhost:3001">
<img src="http://localhost:3001/img/ok.svg" width="40" alt="localhost:3001 (apex)">
<img src="http://localhost:4000/img/ok.svg" width="40" alt="4000 /img/ 아래">
<img src="http://localhost:4000/other.svg" width="40" alt="4000 /img/ 밖">`,
  },
  {
    id: "two-headers",
    title: "정책 두 개 = 교집합",
    mode: "two-headers",
    policy: "img-src *",
    policy2: "img-src 'self'",
    html: `<img src="http://localhost:3001/img/ok.svg" width="40" alt="CDN 이미지">`,
  },
  {
    id: "nonce-vs-unsafe-inline",
    title: "nonce 가 있으면 'unsafe-inline' 은 무시된다",
    mode: "header",
    policy: "script-src 'unsafe-inline' 'nonce-c2VtaW5hcg'",
    html: `<script>document.body.append("❓ nonce 없는 인라인 script")</script>
<script nonce="c2VtaW5hcg">document.body.append("✅ nonce 있는 인라인 script")</script>`,
  },
  {
    id: "meta",
    title: "<meta> 로 전달 — 위치와 한계",
    mode: "meta",
    policy: "script-src 'self'; frame-ancestors 'none'; report-uri /try/report",
    html: `<script>document.body.append("인라인 script (meta 뒤)")</script>`,
  },
  {
    id: "report-only",
    title: "enforce + Report-Only 동시에",
    mode: "enforce+report",
    policy: "img-src 'self'",
    policy2: "script-src 'self'",
    html: `<img src="http://localhost:3001/img/ok.svg" width="40" alt="CDN 이미지">
<script>document.body.append("✅ 인라인 script (Report-Only 라 실행됨)")</script>`,
  },
  {
    id: "frame-ancestors",
    title: "frame-ancestors — 헤더로 보낼 때",
    mode: "header",
    policy: "frame-ancestors 'none'",
    html: `<p>이 문서가 보이면 iframe 삽입이 허용된 것</p>`,
  },
];

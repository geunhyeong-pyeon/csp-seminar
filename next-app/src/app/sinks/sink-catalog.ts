// XSS "싱크(sink)" 카탈로그 — 사용자 입력이 도착했을 때 코드로 해석될 수 있는 자리.
// guard: 이 자리를 React/Next 가 구조적으로 막아 주는가 (CSP 없이, React 19 · Next 16 기준).
export const URL_PAYLOAD = "javascript:alert('XSS @ ' + document.domain)";
export const HTML_PAYLOAD = `<img src=x onerror="alert('XSS @ ' + document.domain)">`;
export const SCRIPT_BREAKOUT_PAYLOAD = `</script><script>alert('XSS @ ' + document.domain)</script>`;
export const PROPS_PAYLOAD = `{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=\\"alert('XSS @ ' + document.domain)\\">"}}`;
export const OPEN_REDIRECT_PAYLOAD = "https://example.com/fake-login";

export type SinkGuard = "react" | "next" | "browser" | "none";

export interface Sink {
  id: string;
  title: string;
  code: string;
  payload: string;
  guard: SinkGuard;
  note: string;
}

export const SINKS: Sink[] = [
  { id: "text", title: "{text} — 텍스트 자식", code: "<p>{input}</p>", payload: HTML_PAYLOAD, guard: "react", note: "React 가 HTML 이스케이프한다. 태그가 글자로 보인다." },
  { id: "attr", title: "일반 속성 값", code: "<input value={input} />", payload: `"><img src=x onerror=alert(1)>`, guard: "react", note: "속성 값도 이스케이프된다. 따옴표를 닫고 탈출할 수 없다." },
  { id: "a-href", title: "<a href>", code: "<a href={input}>", payload: URL_PAYLOAD, guard: "react", note: "React 19 가 javascript: URL 을 '에러를 던지는 URL' 로 바꿔 렌더링한다 (react-dom sanitizeURL)." },
  { id: "link-href", title: "<Link href> (next/link)", code: "<Link href={input}>", payload: URL_PAYLOAD, guard: "next", note: "렌더링은 React 가, 클릭 시 내비게이션은 Next 라우터가 javascript: 를 차단한다." },
  { id: "router-push", title: "router.push()", code: "router.push(input)", payload: URL_PAYLOAD, guard: "next", note: "Next 라우터의 navigate() 가 isJavaScriptURLString 이면 throw." },
  { id: "form-action", title: "<form action> / <button formAction>", code: "<form action={input}>", payload: URL_PAYLOAD, guard: "react", note: "action · formAction 도 sanitizeURL 대상." },
  { id: "iframe-src", title: "<iframe src>", code: "<iframe src={input} />", payload: URL_PAYLOAD, guard: "react", note: "src 도 sanitizeURL 대상." },
  { id: "object-data", title: "<object data>", code: "<object data={input} />", payload: URL_PAYLOAD, guard: "browser", note: "React 는 data 속성을 검사하지 않는다. 현재 브라우저가 object 의 javascript: 를 실행하지 않을 뿐 — 프레임워크 보장이 아니다. (CSP object-src 'none' 이 정답)" },
  { id: "location", title: "location.href = …", code: "window.location.href = input", payload: URL_PAYLOAD, guard: "none", note: "React 를 거치지 않는 브라우저 API. 그대로 실행된다." },
  { id: "window-open", title: "window.open()", code: "window.open(input)", payload: URL_PAYLOAD, guard: "none", note: "새 창이 우리 origin 을 물려받아 실행된다." },
  { id: "inner-html", title: "dangerouslySetInnerHTML", code: "<div dangerouslySetInnerHTML={{ __html: input }} />", payload: HTML_PAYLOAD, guard: "none", note: "이름 그대로. 문자열을 HTML 로 파싱한다." },
  { id: "ref-inner-html", title: "ref.current.innerHTML", code: "ref.current.innerHTML = input", payload: HTML_PAYLOAD, guard: "none", note: "React 밖에서 DOM 을 직접 만지는 코드 (에디터·차트 라이브러리도 같은 경로)." },
  { id: "srcdoc", title: "<iframe srcDoc>", code: "<iframe srcDoc={input} />", payload: HTML_PAYLOAD, guard: "none", note: "srcdoc 은 'HTML 문서 전체' 를 받는 속성. 부모와 같은 origin 으로 실행된다." },
  { id: "json-ld", title: "JSON-LD / 인라인 <script> 직렬화", code: `<script type="application/ld+json"\n  dangerouslySetInnerHTML={{ __html: JSON.stringify({ name: input }) }} />`, payload: SCRIPT_BREAKOUT_PAYLOAD, guard: "none", note: "JSON.stringify 는 </script> 를 이스케이프하지 않는다. HTML 파서가 먼저 script 를 닫아 버린다. Next 공식 문서도 '<' 를 \\u003c 로 치환하라고 안내." },
  { id: "spread-props", title: "props 스프레드 {...obj}", code: "<div {...JSON.parse(input)} />", payload: PROPS_PAYLOAD, guard: "none", note: "외부 데이터를 props 로 펼치면 dangerouslySetInnerHTML 키까지 들어온다." },
  { id: "open-redirect", title: "오픈 리다이렉트 (<Link> / redirect())", code: "<Link href={searchParams.next}>", payload: OPEN_REDIRECT_PAYLOAD, guard: "none", note: "XSS 는 아니지만 링크 싱크의 대표 사고. 우리 도메인을 믿고 누른 사용자를 피싱 페이지로 보낸다." },
];

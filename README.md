# CSP 세미나 — 라이브 데모

Content-Security-Policy(CSP)를 처음 보는 사람도 "왜 필요한지 → 어떻게 막는지 → 실무에서 어떻게 거는지"를
직접 눈으로 확인할 수 있게 만든 데모 저장소입니다.

| 폴더 | 내용 | 설치 |
| --- | --- | --- |
| `playground/` | 같은 취약한 페이지에 CSP만 바꿔 가며 공격이 막히는지 보는 랩 9개 | 없음 (Node 20+) |
| `next-app/` | Next.js 16 에서 nonce 기반 strict CSP 를 실제로 거는 방법 | `pnpm install` |

---

## 1. Playground — CSP 지시어별 공격/방어

```bash
node playground/server.mjs
```

세 개의 서버가 뜹니다. **origin 이 다르다는 점**이 데모의 핵심입니다.

| 주소 | 역할 |
| --- | --- |
| http://localhost:3000 | 우리 앱. `?q=` 를 이스케이프 없이 출력하는 **취약한 검색 페이지** |
| http://localhost:3001 | 우리가 "신뢰하는" 서드파티 CDN (JSONP 엔드포인트가 있음) |
| http://localhost:4000 | 공격자 서버. 탈취한 데이터가 실시간으로 쌓이는 대시보드 |

브라우저 창 두 개를 나란히 띄워 두고(왼쪽 :3000, 오른쪽 :4000) 진행하세요.
각 랩 화면에서 공격 페이로드를 클릭하면 `?q=` 에 주입되고, 아래 **실행 로그 / CSP 위반** 목록과
공격자 대시보드에서 결과를 확인할 수 있습니다. 토글로 정책을 켜고 끄면서 비교합니다.

| 랩 | 정책 | 보여 주는 것 |
| --- | --- | --- |
| 1 | 없음 | 인라인 핸들러·외부 스크립트 모두 실행 → 쿠키 탈취 |
| 2 | `script-src 'self' 'unsafe-inline'` | 외부는 막지만 인라인 주입은 그대로 — `'unsafe-inline'` = CSP 무력화 |
| 3 | `script-src 'self' <cdn>` | allowlist 는 허용한 호스트의 **JSONP** 하나로 우회된다 |
| 4 | `script-src 'nonce-…'` | 이번 응답의 nonce 를 가진 스크립트만 실행. 고정 nonce(`static=1`)면 무의미 |
| 5 | `+ 'strict-dynamic'` | nonce 로 신뢰한 로더가 `createElement` 로 추가한 스크립트에 신뢰 전파 (gtag.js 패턴) |
| 6 | `connect-src` / `default-src` | 공급망 공격: script-src 로는 못 막는 "우리 번들 속 악성 의존성"의 유출 경로 차단 |
| 7 | `base-uri` · `form-action` · `object-src` | `<base>` 주입으로 우리 nonce 스크립트 하이재킹, 가짜 로그인 폼으로 비밀번호 전송 |
| 8 | `Content-Security-Policy-Report-Only` | 막지 않고 보고만. `/violations` 에 리포트 수집. 라이브러리의 `new Function` 프로브(zod) 함정 |
| 9 | `frame-ancestors` | 클릭재킹: 공격자 페이지(`:4000/clickjack`)가 우리 페이지를 투명 iframe 으로 덮음 |

### CSP 정책 실험실 — `/try`

정책 · 전달 방식(헤더 / Report-Only / 헤더 2개 / `<meta>`) · HTML 을 직접 바꿔 보며 브라우저 판정을 확인하는 페이지.
실험 문서는 iframe 으로 뜨고, 그 문서에서 난 위반 리포트(`report-uri`)가 옆에 쌓입니다.
프리셋: 기본 · 따옴표 실수 · 인라인 판정 종류 · `default-src` 폴백 · `*` 와 `data:` · 호스트/서브도메인/경로 매칭 · 정책 두 개 = 교집합 · nonce 와 `'unsafe-inline'` · `<meta>` 의 한계 · enforce + Report-Only · `frame-ancestors`.

> ⚠️ 의도적으로 취약하게 만든 코드입니다. 로컬 데모 용도로만 실행하세요.

## 2. next-app — Next.js 16 실전 적용

```bash
cd next-app
pnpm install
pnpm test                       # 정책 빌더 계약 테스트
pnpm build && pnpm start        # http://localhost:3100 (nonce 는 프로덕션 빌드로 확인하는 게 정확)
```

| 파일 | 역할 |
| --- | --- |
| `src/lib/content-security-policy.ts` | 정책을 만드는 **순수 함수**. 테스트 가능하게 proxy 밖으로 분리 |
| `src/proxy.ts` | 요청마다 nonce 생성 → ① 요청 헤더(Next 가 읽어서 자기 스크립트에 nonce 스탬핑) ② 응답 헤더(브라우저가 집행) |
| `src/app/layout.tsx` | `headers()` 로 nonce 를 읽어 우리 인라인 스크립트·`<Script>` 에 직접 전달 |
| `public/analytics-loader.js` | 스크립트가 스크립트를 부르는 로더 → `'strict-dynamic'` |
| `src/lib/zod-jitless.ts` | zod v4 의 `new Function("")` 프로브가 위반 리포트를 오염시키는 문제 차단 |
| `next.config.ts` | nonce 가 필요 없는 정적 floor (proxy 가 안 닿는 경로용) |
| `src/app/api/csp-report/route.ts` | `report-uri` 수집 엔드포인트 |
| `src/app/sinks/` | **XSS 싱크 지도** — 입력이 도착하는 자리 16곳에서 React·Next 가 막는 것 / 못 막는 것 |

환경 변수로 동작을 바꿔 볼 수 있습니다.

```bash
CSP_MODE=off pnpm start                 # CSP 끄기 → /xss, /sinks 에서 프레임워크만의 방어 확인
CSP_MODE=report-only pnpm start         # 막지 않고 보고만
NEXT_PUBLIC_ZOD_JITLESS=0 pnpm build    # zod 조치 해제 → 홈에서 [report|enforce] script-src ← eval 위반 재현
```

확인 포인트

- 새로고침마다 nonce 가 바뀐다 (`curl -sI localhost:3100 | grep -i content-security`).
- View Source 에서 모든 `<script nonce="…">` 가 헤더의 nonce 와 같다. (DevTools Elements 에서는 브라우저가 nonce 값을 숨긴다.)
- 빌드 결과의 모든 페이지가 `ƒ (Dynamic)` — nonce 는 요청마다 달라야 하므로 정적 프리렌더가 불가능하다.
- `/xss` 의 `<img onerror>` 가 `script-src-attr` 위반으로 차단되고 `/api/csp-report` 로 리포트가 온다.

## 참고

- [MDN — Content Security Policy](https://developer.mozilla.org/docs/Web/HTTP/CSP)
- [web.dev — Mitigate XSS with a strict CSP](https://web.dev/articles/strict-csp)
- [Google — CSP Is Dead, Long Live CSP! (allowlist 우회 연구)](https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/)
- [Next.js — Content Security Policy 가이드](https://nextjs.org/docs/app/guides/content-security-policy)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

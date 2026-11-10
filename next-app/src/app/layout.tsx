import Script from "next/script";
import { headers } from "next/headers";
import type { ReactNode } from "react";

import { Providers } from "./providers";
import "./globals.css";

export const metadata = { title: "CSP in Next.js" };

// 페이지에서 일어난 CSP 위반을 화면에 보여 주기 위한 기록기.
// 우리 인라인 스크립트도 nonce 가 있어야 실행된다 — 그래서 nonce 를 직접 넘긴다.
const VIOLATION_RECORDER = `
window.__cspViolations = [];
document.addEventListener("securitypolicyviolation", (event) => {
  window.__cspViolations.push({
    disposition: event.disposition,
    directive: event.effectiveDirective,
    blocked: event.blockedURI || "inline",
    sample: event.sample,
  });
  window.dispatchEvent(new Event("csp-violation"));
});`;

export default async function RootLayout({ children }: { children: ReactNode }) {
  // proxy 가 요청 헤더에 심어 둔 이번 요청의 nonce. headers() 호출 = 동적 렌더링.
  const nonce = (await headers()).get("x-nonce") ?? undefined;

  return (
    <html lang="ko">
      <head>
        {/* HTML 파싱 중(이미지 onerror 등) 발생하는 위반까지 잡으려면 <head> 맨 앞에서 실행돼야 한다 */}
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: VIOLATION_RECORDER }} />
      </head>
      <body>
        {/* gtag.js 같은 "로더" 스크립트. 자기가 또 다른 스크립트를 추가한다 → 'strict-dynamic' 필요 */}
        <Script src="/analytics-loader.js" strategy="afterInteractive" nonce={nonce} />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

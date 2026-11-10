import type { NextConfig } from "next";

// 정적 헤더는 빌드 시점에 고정된다 → 요청마다 바뀌어야 하는 nonce는 여기에 실을 수 없다.
// 그래서 여기에는 nonce가 필요 없는 "바닥(floor)" 지시어만 둔다.
// proxy가 매칭되지 않는 경로(정적 파일, 매처 밖 페이지)도 최소한 이것은 받는다.
const STATIC_CSP_FLOOR = "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";

const nextConfig: NextConfig = {
  headers: async () => [
    {
      source: "/:path*",
      headers: [
        { key: "Content-Security-Policy", value: STATIC_CSP_FLOOR },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      ],
    },
  ],
};

export default nextConfig;

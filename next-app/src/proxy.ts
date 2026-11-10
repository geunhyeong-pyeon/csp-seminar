import { NextResponse, type NextRequest } from "next/server";

import {
  buildContentSecurityPolicy,
  resolveCspHeaderName,
  type CspMode,
} from "@/lib/content-security-policy";

const readCspMode = (): CspMode => {
  const mode = process.env.CSP_MODE;
  return mode === "report-only" || mode === "off" ? mode : "enforce";
};

export function proxy(request: NextRequest) {
  const headerName = resolveCspHeaderName(readCspMode());
  if (headerName == null) {
    return NextResponse.next();
  }

  // 요청마다 새 난수. 예측 불가능해야 하고, 재사용하면 안 된다.
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const policy = buildContentSecurityPolicy({
    nonce,
    isDevelopment: process.env.NODE_ENV === "development",
  });

  // ① 요청 헤더: Next 가 렌더링 중에 여기서 nonce 를 꺼내 자기 스크립트 전부에 붙인다.
  //    (Next 는 request 의 content-security-policy, 없으면 -report-only 헤더를 읽는다.
  //     next/dist/server/route-modules/app-page/parse-request-headers.js)
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", policy);

  const response = NextResponse.next({ request: { headers: requestHeaders } });

  // ② 응답 헤더: 브라우저가 실제로 집행하는 정책.
  response.headers.set(headerName, policy);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};

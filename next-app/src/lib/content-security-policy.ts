export type CspMode = "enforce" | "report-only" | "off";

export const CSP_HEADER = "Content-Security-Policy";
export const CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

interface Input {
  nonce: string;
  isDevelopment: boolean;
}

/** `null` = 정책 헤더를 아예 보내지 않는다 (nonce도 만들 필요 없음). */
export const resolveCspHeaderName = (mode: CspMode): string | null => {
  if (mode === "enforce") return CSP_HEADER;
  if (mode === "report-only") return CSP_REPORT_ONLY_HEADER;
  return null;
};

export const buildContentSecurityPolicy = ({ nonce, isDevelopment }: Input): string => {
  // 빈 nonce면 `'nonce-'` 가 되어 아무 스크립트도 허용하지 않는(또는 의미 없는) 정책이 된다.
  if (nonce.trim() === "") {
    throw new Error("CSP nonce must be a non-empty string");
  }

  const directives: Record<string, readonly string[]> = {
    "default-src": ["'self'"],
    "script-src": [
      "'self'",
      `'nonce-${nonce}'`,
      "'strict-dynamic'",
      // React dev 모드(에러 스택 복원, HMR)가 eval을 쓴다. 프로덕션 빌드에는 넣지 않는다.
      ...(isDevelopment ? ["'unsafe-eval'"] : []),
    ],
    // React가 style prop을 인라인 style 속성으로 직렬화하므로 style은 nonce로 잠그지 않는다.
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "blob:", "data:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'", ...(isDevelopment ? ["ws:"] : [])],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'self'"],
    "report-uri": ["/api/csp-report"],
  };

  return Object.entries(directives)
    .map(([directive, sources]) => `${directive} ${sources.join(" ")}`)
    .join("; ");
};

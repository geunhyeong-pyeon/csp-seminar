// 브라우저가 report-uri 로 보내는 위반 리포트 수집 엔드포인트.
// 실무에서는 직접 만들기보다 Sentry 같은 수집 서비스의 security endpoint 를 report-uri 에 넣는 것이 가장 싸다.
export async function POST(request: Request) {
  const body = (await request.json().catch(() => null)) as { "csp-report"?: Record<string, unknown> } | null;
  const report = body?.["csp-report"];
  if (report) {
    process.stdout.write(`[csp-report] ${String(report["violated-directive"])} ← ${String(report["blocked-uri"])}\n`);
  }
  return new Response(null, { status: 204 });
}

import { z } from "zod";

// zod v4는 첫 z.object() 생성 시 `new Function("")` 으로 eval 가능 여부를 확인한다.
// try/catch 로 감싸져 있어 동작은 정상이지만, strict CSP 에서는 위반 이벤트/리포트가 남는다.
// jitless 면 그 확인 자체를 건너뛴다. 서버에는 CSP 가 없으므로 브라우저에서만 끈다.
// NEXT_PUBLIC_ZOD_JITLESS=0 으로 실행하면 이 조치를 끄고 위반을 재현할 수 있다.
if (typeof window !== "undefined" && process.env.NEXT_PUBLIC_ZOD_JITLESS !== "0") {
  z.config({ jitless: true });
}

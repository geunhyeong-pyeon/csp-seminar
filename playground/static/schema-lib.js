// zod v4 의 eval 가능 여부 프로브(core/util.js allowsEval)와 같은 패턴.
// try/catch 로 감쌌기 때문에 앱은 절대 깨지지 않는다 — 그런데 CSP 위반 리포트는 남는다.
const isJitless = new URL(document.currentScript.src).searchParams.get("jitless") === "1";
let canEval = false;
if (!isJitless) {
  try {
    new Function("");
    canEval = true;
  } catch {
    canEval = false;
  }
}
lab.log("ok", `스키마 라이브러리 로드 (jitless=${isJitless}, eval 가능=${canEval}) — 앱은 정상 동작`);

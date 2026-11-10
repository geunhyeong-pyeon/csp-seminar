// 같은 origin 의 외부 script 안에서 문자열을 코드로 바꾸는 API 들
const attempt = (label, run) => {
  try {
    run();
    document.addEventListener("DOMContentLoaded", () => document.body.append(` ✅ ${label} 실행됨`));
  } catch {
    document.addEventListener("DOMContentLoaded", () => document.body.append(` ⛔ ${label} 차단 (EvalError)`));
  }
};
attempt("eval()", () => eval("1 + 1"));
attempt("new Function()", () => new Function("return 1")());
setTimeout("document.body.append(' ✅ setTimeout(문자열) 실행됨')", 0);

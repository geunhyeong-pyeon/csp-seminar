// 우리가 쓰는 (가상의) 화면 라이브러리: data-calc 속성의 수식을 계산해 채운다.
// new Function 을 쓰므로 'unsafe-eval' 이 없으면 계산이 실패한다.
for (const element of document.querySelectorAll("[data-calc]")) {
  try {
    element.textContent = String(new Function(`return (${element.dataset.calc})`)());
    lab.log("ok", `calc-lib: data-calc="${element.dataset.calc}" 계산됨`);
  } catch {
    element.textContent = "계산 실패";
    lab.log("fail", `calc-lib: data-calc 계산 실패 (EvalError — 'unsafe-eval' 없음)`);
  }
}

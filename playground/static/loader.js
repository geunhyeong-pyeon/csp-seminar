// gtag.js 같은 "로더" 역할. 자신은 nonce로 신뢰받았고, 다른 스크립트를 동적으로 추가한다.
const script = document.createElement("script");
script.src = "http://localhost:3001/analytics.js";
script.onerror = () => lab.log("fail", "loader.js 가 추가한 서드파티 analytics.js 가 차단됨");
document.head.appendChild(script);
lab.log("ok", "loader.js (nonce) 실행됨 → createElement 로 analytics.js 추가");

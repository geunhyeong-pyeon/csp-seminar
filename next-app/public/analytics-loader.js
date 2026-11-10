// gtag.js 흉내. nonce 로 신뢰받은 이 스크립트가 다른 스크립트를 동적으로 추가한다.
// 'strict-dynamic' 이 없으면 아래 스크립트는 nonce 가 없어서 차단된다.
const script = document.createElement("script");
script.src = "/analytics-collect.js";
document.head.appendChild(script);

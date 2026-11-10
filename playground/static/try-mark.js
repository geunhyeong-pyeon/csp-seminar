const label = document.currentScript?.dataset.label ?? "외부 script";
document.addEventListener("DOMContentLoaded", () => document.body.append(`✅ ${label} 실행됨`));

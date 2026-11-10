import Link from "next/link";

import { ViolationPanel } from "../violation-panel";

// 일부러 만든 취약점: 검색어를 HTML 로 그대로 렌더링한다.
// React 의 기본 이스케이프를 dangerouslySetInnerHTML 로 우회한 상황 = 실무에서 XSS 가 생기는 대표 경로.
export default async function XssPage({ searchParams }: PageProps<"/xss">) {
  const { q } = await searchParams;
  const searchTerm = typeof q === "string" ? q : "";

  return (
    <main>
      <h1>dangerouslySetInnerHTML 로 생긴 XSS</h1>
      <div className="card" dangerouslySetInnerHTML={{ __html: `"${searchTerm}" 검색 결과 없음` }} />
      <p>
        CSP_MODE=off 로 띄우면 alert 가 뜨고, enforce 면 아래 위반 목록에 <code>script-src-attr</code> 가 찍힌다.
      </p>
      <ViolationPanel />
      <Link href="/">← 홈</Link>
    </main>
  );
}

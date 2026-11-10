import Link from "next/link";
import { headers } from "next/headers";

import { SignupForm } from "./signup-form";
import { ViolationPanel } from "./violation-panel";

export default async function HomePage() {
  const requestHeaders = await headers();
  const nonce = requestHeaders.get("x-nonce");
  const policy = requestHeaders.get("content-security-policy");

  return (
    <main>
      <h1>Next.js 16 + nonce 기반 strict CSP</h1>
      <p>
        새로고침할 때마다 nonce 가 바뀐다. 개발자도구 Elements 에서 <code>&lt;script nonce&gt;</code> 를 확인해 보자
        (브라우저는 보안상 nonce 속성 값을 DOM 에서 숨긴다 — View Source 로 보면 보인다).
      </p>
      <dl className="card">
        <dt>이번 요청의 nonce</dt>
        <dd>
          <code>{nonce ?? "(CSP_MODE=off)"}</code>
        </dd>
        <dt>정책</dt>
        <dd>
          <pre>{policy?.replaceAll("; ", ";\n") ?? "(없음)"}</pre>
        </dd>
      </dl>
      <SignupForm />
      <ViolationPanel />
      <p>
        <Link href="/xss?q=%3Cimg%20src%3Dx%20onerror%3D%22alert(document.cookie)%22%3E">
          XSS 페이지로 이동 (dangerouslySetInnerHTML)
        </Link>
      </p>
    </main>
  );
}

import Link from "next/link";

import { ClientSink } from "./client-sinks";
import { SINKS } from "./sink-catalog";

const GUARD_LABEL = {
  react: "🛡️ React 가 막음",
  next: "🛡️ Next 가 막음",
  browser: "⚠️ 브라우저가 우연히 막음",
  none: "💀 아무도 안 막음",
} as const;

const CLIENT_SINKS = new Set(["a-href", "link-href", "router-push", "form-action", "location", "window-open", "ref-inner-html", "open-redirect"]);

// 사용자 입력이 "어느 자리"에 도착하느냐에 따라 React/Next 가 막아 주는지가 갈린다.
// CSP 없이 프레임워크만의 방어를 보려면 CSP_MODE=off 로 실행한다.
export default async function SinksPage({ searchParams }: PageProps<"/sinks">) {
  const { sink: selectedId, input } = await searchParams;
  const sink = SINKS.find((candidate) => candidate.id === selectedId);
  const payload = typeof input === "string" ? input : (sink?.payload ?? "");

  return (
    <main>
      <h1>XSS 싱크 지도 — React · Next 는 어디까지 막아 주나</h1>
      <ul className="sink-list">
        {SINKS.map((candidate) => (
          <li key={candidate.id}>
            <Link href={`/sinks?sink=${candidate.id}`}>{candidate.title}</Link> <span>{GUARD_LABEL[candidate.guard]}</span>
          </li>
        ))}
      </ul>

      {sink && (
        <section className="card">
          <h2>{sink.title}</h2>
          <pre>{sink.code}</pre>
          <p>
            입력: <code>{payload}</code>
          </p>
          <p>
            <b>{GUARD_LABEL[sink.guard]}</b> — {sink.note}
          </p>

          {CLIENT_SINKS.has(sink.id) && <ClientSink id={sink.id} payload={payload} />}
          {sink.id === "text" && <p>{payload}</p>}
          {sink.id === "attr" && <input defaultValue={payload} />}
          {sink.id === "iframe-src" && <iframe src={payload} title="iframe-src" />}
          {sink.id === "object-data" && <object data={payload} title="object-data" />}
          {sink.id === "inner-html" && <div dangerouslySetInnerHTML={{ __html: payload }} />}
          {sink.id === "srcdoc" && <iframe srcDoc={payload} title="srcdoc" />}
          {sink.id === "json-ld" && (
            <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify({ name: payload }) }} />
          )}
          {sink.id === "spread-props" && <div {...JSON.parse(payload)} />}
        </section>
      )}
    </main>
  );
}

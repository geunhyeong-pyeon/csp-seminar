"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

interface Props {
  id: string;
  payload: string;
}

const RefInnerHtml = ({ payload }: { payload: string }) => {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.innerHTML = payload;
  }, [payload]);
  return <div ref={ref} />;
};

export const ClientSink = ({ id, payload }: Props) => {
  const router = useRouter();
  const [error, setError] = useState("");

  const run = (action: () => void) => {
    try {
      action();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  };

  return (
    <div className="sink-stage">
      {id === "a-href" && <a href={payload}>클릭: &lt;a href&gt;</a>}
      {id === "link-href" && <Link href={payload}>클릭: &lt;Link href&gt;</Link>}
      {id === "router-push" && <button onClick={() => run(() => router.push(payload))}>router.push(input)</button>}
      {id === "form-action" && (
        <form action={payload}>
          <button>form 제출</button>
        </form>
      )}
      {id === "location" && <button onClick={() => run(() => (window.location.href = payload))}>location.href = input</button>}
      {id === "window-open" && <button onClick={() => run(() => window.open(payload))}>window.open(input)</button>}
      {id === "ref-inner-html" && <RefInnerHtml payload={payload} />}
      {id === "open-redirect" && <Link href={payload}>로그인 후 원래 페이지로 돌아가기</Link>}
      {error && <p className="fail">throw: {error}</p>}
    </div>
  );
};

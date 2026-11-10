"use client";

import { useSyncExternalStore } from "react";

interface Violation {
  disposition: string;
  directive: string;
  blocked: string;
  sample?: string;
}

declare global {
  interface Window {
    __cspViolations?: Violation[];
    __analytics?: string[];
  }
}

const EMPTY: Violation[] = [];

const subscribe = (onChange: () => void) => {
  window.addEventListener("csp-violation", onChange);
  return () => window.removeEventListener("csp-violation", onChange);
};

const getSnapshot = () => window.__cspViolations?.slice() ?? EMPTY;
let cached: Violation[] = EMPTY;
const getStableSnapshot = () => {
  const next = getSnapshot();
  if (next.length !== cached.length) cached = next;
  return cached;
};

export const ViolationPanel = () => {
  const violations = useSyncExternalStore(subscribe, getStableSnapshot, () => EMPTY);

  return (
    <section>
      <h2>CSP 위반 ({violations.length}건)</h2>
      {violations.length === 0 && <p className="ok">위반 없음</p>}
      <ul>
        {violations.map((violation, index) => (
          <li key={index} className={violation.disposition === "report" ? "report" : "fail"}>
            [{violation.disposition}] {violation.directive} ← {violation.blocked}
            {violation.sample && ` · "${violation.sample}"`}
          </li>
        ))}
      </ul>
    </section>
  );
};

"use client";

import { useState } from "react";
import { z } from "zod";

// 모듈 평가 시점에 z.object() 가 만들어진다 → zod 의 eval 프로브가 이때 돈다.
const signupSchema = z.object({
  email: z.email(),
  password: z.string().min(8),
});

export const SignupForm = () => {
  const [message, setMessage] = useState("");

  const handleSubmit = (formData: FormData) => {
    const result = signupSchema.safeParse(Object.fromEntries(formData));
    setMessage(result.success ? "✅ 유효합니다" : `⛔ ${result.error.issues[0]?.path.join(".")} 오류`);
  };

  return (
    <form action={handleSubmit} className="card">
      <h2>zod 로 검증하는 폼</h2>
      <input name="email" placeholder="email" />
      <input name="password" type="password" placeholder="password (8자 이상)" />
      <button>검증</button>
      {message && <p>{message}</p>}
    </form>
  );
};

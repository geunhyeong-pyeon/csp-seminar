"use client";

// side-effect import: 클라이언트에서 첫 zod 스키마가 만들어지기 전에 평가되어야 한다.
import "@/lib/zod-jitless";

import type { ReactNode } from "react";

export const Providers = ({ children }: { children: ReactNode }) => children;

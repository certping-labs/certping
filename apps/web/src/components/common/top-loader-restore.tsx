// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback } from "react";
import { useTopLoader } from "nextjs-toploader";

import { usePageRestore } from "@/hooks/use-page-restore";

export function TopLoaderRestore() {
  const topLoader = useTopLoader();

  usePageRestore(
    useCallback(() => {
      topLoader.done(true);
      topLoader.remove();
      document.documentElement.classList.remove("nprogress-busy");
    }, [topLoader]),
  );

  return null;
}

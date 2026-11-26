// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useEffect, useRef } from "react";

export function usePageRestore(onRestore: () => void): void {
  const onRestoreRef = useRef(onRestore);

  useEffect(() => {
    onRestoreRef.current = onRestore;
  }, [onRestore]);

  useEffect(() => {
    const notifyRestore = () => onRestoreRef.current();
    const handlePageShow = (event: PageTransitionEvent) => {
      if (event.persisted || wasRestoredFromHistory()) {
        notifyRestore();
      }
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        notifyRestore();
      }
    };

    window.addEventListener("pageshow", handlePageShow);
    window.addEventListener("focus", notifyRestore);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      window.removeEventListener("pageshow", handlePageShow);
      window.removeEventListener("focus", notifyRestore);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);
}

function wasRestoredFromHistory(): boolean {
  if (
    typeof performance === "undefined" ||
    typeof performance.getEntriesByType !== "function"
  ) {
    return false;
  }

  const [navigationEntry] = performance.getEntriesByType("navigation");

  return (
    typeof PerformanceNavigationTiming !== "undefined" &&
    navigationEntry instanceof PerformanceNavigationTiming &&
    navigationEntry.type === "back_forward"
  );
}

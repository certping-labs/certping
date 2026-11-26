// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect } from "react";

import { useNetworkStatusStore } from "@/lib/network-status";

export function NetworkStatusProvider(props: { children: React.ReactNode }) {
  const clearNetworkIssue = useNetworkStatusStore(
    (state) => state.clearNetworkIssue,
  );
  const reportNetworkIssue = useNetworkStatusStore(
    (state) => state.reportNetworkIssue,
  );

  useEffect(() => {
    const clearBrowserIssueWhenReachable = () => {
      const currentIssue = useNetworkStatusStore.getState().issue;

      if (window.navigator.onLine && currentIssue?.source === "browser") {
        clearNetworkIssue();
      }
    };
    const handleOnline = () => clearBrowserIssueWhenReachable();
    const handleOffline = () =>
      reportNetworkIssue(
        "Your browser appears to be offline. Check your connection, VPN, or corporate proxy before retrying.",
        "browser",
      );
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        clearBrowserIssueWhenReachable();
      }
    };

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);
    window.addEventListener("focus", clearBrowserIssueWhenReachable);
    window.addEventListener("pageshow", clearBrowserIssueWhenReachable);
    document.addEventListener("visibilitychange", handleVisibilityChange);

    if (!window.navigator.onLine) {
      handleOffline();
    }

    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
      window.removeEventListener("focus", clearBrowserIssueWhenReachable);
      window.removeEventListener("pageshow", clearBrowserIssueWhenReachable);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [clearNetworkIssue, reportNetworkIssue]);

  return <>{props.children}</>;
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { useCallback, useEffect } from "react";

const DEFAULT_WARNING_MESSAGE =
  "You have unsaved changes. Are you sure you want to leave this page?";

function isSameUrl(targetUrl: unknown): boolean {
  if (!targetUrl) {
    return true;
  }

  const target = typeof targetUrl === "string" ? targetUrl : String(targetUrl);
  if (!target.trim()) {
    return true;
  }

  try {
    const current = new URL(window.location.href);
    const next = new URL(target, current);
    return current.href === next.href;
  } catch {
    // If URL parsing fails, assume it is a navigation attempt.
    return false;
  }
}

export function useUnsavedChangesWarning(
  shouldWarn: boolean,
  message = DEFAULT_WARNING_MESSAGE,
): { confirmLeave: () => boolean } {
  useEffect(() => {
    if (!shouldWarn) {
      return;
    }

    const confirmNavigation = (targetUrl?: unknown): boolean => {
      // App Router internal state updates can call pushState/replaceState with the same URL.
      // Do not annoy the user for no-op navigations.
      if (isSameUrl(targetUrl)) {
        return true;
      }
      return window.confirm(message);
    };

    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };

    const originalPushState = window.history.pushState.bind(window.history);
    const originalReplaceState = window.history.replaceState.bind(
      window.history,
    );
    window.history.pushState = (
      data: unknown,
      unusedTitle: string,
      url?: string | URL | null,
    ) => {
      if (!confirmNavigation(url)) {
        return;
      }
      originalPushState(data, unusedTitle, url);
    };
    window.history.replaceState = (
      data: unknown,
      unusedTitle: string,
      url?: string | URL | null,
    ) => {
      if (!confirmNavigation(url)) {
        return;
      }
      originalReplaceState(data, unusedTitle, url);
    };

    const handleLinkClick = (event: MouseEvent) => {
      const target = event.target;
      if (!(target instanceof Element)) {
        return;
      }

      const anchor = target.closest("a");
      if (!anchor) {
        return;
      }

      // Ignore new-tab / new-window / modified clicks, and in-page anchors.
      if (
        anchor.target === "_blank" ||
        event.metaKey ||
        event.ctrlKey ||
        event.shiftKey ||
        event.altKey
      ) {
        return;
      }
      const href = anchor.getAttribute("href") || "";
      if (!href || href.startsWith("#")) {
        return;
      }

      if (!confirmNavigation(href)) {
        event.preventDefault();
        event.stopPropagation();
      }
    };

    // Popstate (browser back/forward, including touchpad gestures) doesn't
    // trigger beforeunload. We insert a history marker so we can intercept
    // back/forward reliably.
    const historyMarker = { __unsaved_changes_warning: true };
    const pushMarker = () => {
      try {
        window.history.pushState(historyMarker, "", window.location.href);
      } catch {
        // Ignore if history is unavailable.
      }
    };
    pushMarker();

    const handlePopState = () => {
      if (!shouldWarn) {
        return;
      }

      const ok = window.confirm(message);
      if (!ok) {
        pushMarker();
        return;
      }

      // User confirmed leaving: remove guard and continue navigating.
      window.removeEventListener("popstate", handlePopState);
      document.removeEventListener("click", handleLinkClick, true);
      window.removeEventListener("beforeunload", handleBeforeUnload);
      window.history.pushState = originalPushState;
      window.history.replaceState = originalReplaceState;
      window.history.back();
    };

    window.addEventListener("beforeunload", handleBeforeUnload);
    window.addEventListener("popstate", handlePopState);
    document.addEventListener("click", handleLinkClick, true);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
      window.removeEventListener("popstate", handlePopState);
      document.removeEventListener("click", handleLinkClick, true);
      window.history.pushState = originalPushState;
      window.history.replaceState = originalReplaceState;
    };
  }, [message, shouldWarn]);

  const confirmLeave = useCallback((): boolean => {
    if (!shouldWarn) {
      return true;
    }
    return window.confirm(message);
  }, [message, shouldWarn]);

  return { confirmLeave };
}

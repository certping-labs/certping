// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import * as React from "react";

import type { ViewMode } from "@/components/ui/view-switcher";

const COMPACT_QUERY = "(max-width: 1023px)";

interface ResponsiveViewModeOptions {
  storageKey: string;
  desktopDefault?: ViewMode;
  compactDefault?: ViewMode;
}

const storageListeners = new Set<() => void>();

function subscribeToCompactScreen(onChange: () => void) {
  const mediaQuery = window.matchMedia(COMPACT_QUERY);
  mediaQuery.addEventListener("change", onChange);
  return () => mediaQuery.removeEventListener("change", onChange);
}

const isCompactScreen = () => window.matchMedia(COMPACT_QUERY).matches;
const isServerCompact = () => false;

function subscribeToStoredViewMode(onChange: () => void) {
  storageListeners.add(onChange);
  window.addEventListener("storage", onChange);
  return () => {
    storageListeners.delete(onChange);
    window.removeEventListener("storage", onChange);
  };
}

function readStoredViewMode(storageKey: string): ViewMode | null {
  try {
    const stored = window.localStorage.getItem(storageKey);
    return stored === "table" || stored === "card" ? stored : null;
  } catch {
    return null;
  }
}

function writeStoredViewMode(storageKey: string, viewMode: ViewMode) {
  try {
    window.localStorage.setItem(storageKey, viewMode);
  } catch {
    return;
  }
  storageListeners.forEach((listener) => listener());
}

export function useResponsiveViewMode({
  storageKey,
  desktopDefault = "table",
  compactDefault = "card",
}: ResponsiveViewModeOptions): [ViewMode, (nextViewMode: ViewMode) => void] {
  const isCompact = React.useSyncExternalStore(
    subscribeToCompactScreen,
    isCompactScreen,
    isServerCompact,
  );
  const storedViewMode = React.useSyncExternalStore(
    subscribeToStoredViewMode,
    () => readStoredViewMode(storageKey),
    () => null,
  );
  const [compactChoice, setCompactChoice] = React.useState<ViewMode | null>(
    null,
  );

  const viewMode = isCompact
    ? (compactChoice ?? compactDefault)
    : (storedViewMode ?? desktopDefault);

  const updateViewMode = React.useCallback(
    (nextViewMode: ViewMode) => {
      setCompactChoice(nextViewMode);
      writeStoredViewMode(storageKey, nextViewMode);
    },
    [storageKey],
  );

  return [viewMode, updateViewMode];
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { startTransition, useSyncExternalStore } from "react";

/**
 * A stand-in for the App Router's URL: `router.replace` changes the query and every
 * `useSearchParams` reader re-renders, as in the browser.
 */
let search = new URLSearchParams();
let pathname = "/settings/domain-ops";
const listeners = new Set<() => void>();

/** Every href passed to `router.replace`, oldest first. */
export const replaced: string[] = [];

/**
 * A page that ping-pongs the URL would replace forever; past this many replaces the URL
 * stops moving, so the loop ends and the test fails on its replace count instead of hanging.
 */
const REPLACE_LOOP_LIMIT = 40;

function setSearch(query: string): void {
  search = new URLSearchParams(query);
  listeners.forEach((listener) => listener());
}

const nativeReplaceState =
  typeof window === "undefined"
    ? null
    : window.history.replaceState.bind(window.history);

/** Moves jsdom's address bar without going through any spy on the history API. */
function moveAddressBar(query: string): void {
  nativeReplaceState?.(null, "", query ? `${pathname}?${query}` : pathname);
}

/** Starts a test on `query` (at `path`) with no navigation recorded. */
export function resetUrl(query = "", path = "/settings/domain-ops"): void {
  replaced.length = 0;
  pathname = path;
  moveAddressBar(query);
  setSearch(query);
}

/**
 * Lands on `query` the way a same-page `<Link>` or back/forward does: the address bar and the
 * search params change, and nothing is recorded as a replace.
 */
export function navigateTo(query: string): void {
  moveAddressBar(query);
  setSearch(query);
}

/**
 * Hands `useSearchParams` readers a query the address bar has already moved past, as a render
 * from an older router transition does.
 */
export function deliverStaleSearch(query: string): void {
  setSearch(query);
}

/**
 * Patches the history API as Next does: `replaceState` or `pushState` with a URL moves the
 * address bar and, in a transition, every `useSearchParams` reader. Returns the spies.
 */
export function followHistory() {
  const nativeReplace = window.history.replaceState.bind(window.history);
  const nativePush = window.history.pushState.bind(window.history);
  const follow =
    (native: History["replaceState"]) =>
    (data: unknown, unused: string, url?: string | URL | null) => {
      native(data, unused, url);
      if (url == null) return;
      const next = new URL(String(url), window.location.href);
      startTransition(() => setSearch(next.search.slice(1)));
    };
  const replaceState = jest
    .spyOn(window.history, "replaceState")
    .mockImplementation(follow(nativeReplace));
  const pushState = jest
    .spyOn(window.history, "pushState")
    .mockImplementation(follow(nativePush));
  return {
    replaceState,
    pushState,
    params: () => new URL(window.location.href).searchParams,
  };
}

const replace = (href: string) => {
  replaced.push(href);
  if (replaced.length > REPLACE_LOOP_LIMIT) return;
  setSearch(href.split("?")[1] ?? "");
};

const noop = () => undefined;

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

export const navigation = {
  useRouter: () => ({ replace, push: noop, back: noop, refresh: noop }),
  usePathname: () => pathname,
  useSearchParams: () =>
    useSyncExternalStore(
      subscribe,
      () => search,
      () => search,
    ),
};

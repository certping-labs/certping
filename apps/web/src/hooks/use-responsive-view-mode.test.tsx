// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { act, renderHook } from "@testing-library/react";

import { useResponsiveViewMode } from "@/hooks/use-responsive-view-mode";

function mockScreen(compact: boolean) {
  const listeners = new Set<() => void>();
  window.matchMedia = ((query: string) => ({
    matches: compact,
    media: query,
    onchange: null,
    addEventListener: (_: string, listener: () => void) =>
      listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) =>
      listeners.delete(listener),
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

describe("useResponsiveViewMode", () => {
  const originalMatchMedia = window.matchMedia;

  beforeEach(() => window.localStorage.clear());
  afterAll(() => {
    window.matchMedia = originalMatchMedia;
  });

  it("uses the stored choice on wide screens and remembers a new one", () => {
    mockScreen(false);
    window.localStorage.setItem("list_view", "card");
    const { result } = renderHook(() =>
      useResponsiveViewMode({ storageKey: "list_view" }),
    );

    expect(result.current[0]).toBe("card");
    act(() => result.current[1]("table"));
    expect(result.current[0]).toBe("table");
    expect(window.localStorage.getItem("list_view")).toBe("table");
  });

  it("falls back to the defaults when nothing valid is stored", () => {
    mockScreen(false);
    window.localStorage.setItem("list_view", "nonsense");
    const { result } = renderHook(() =>
      useResponsiveViewMode({
        storageKey: "list_view",
        desktopDefault: "card",
      }),
    );

    expect(result.current[0]).toBe("card");
  });

  it("starts compact screens on cards and still lets people switch", () => {
    mockScreen(true);
    window.localStorage.setItem("list_view", "table");
    const { result } = renderHook(() =>
      useResponsiveViewMode({ storageKey: "list_view" }),
    );

    expect(result.current[0]).toBe("card");
    act(() => result.current[1]("table"));
    expect(result.current[0]).toBe("table");
  });
});

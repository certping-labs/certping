// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { act, renderHook } from "@testing-library/react";

import { useAnimatedCount } from "@/hooks/use-animated-count";

const createMediaQuery = (matches: boolean): MediaQueryList =>
  ({
    matches,
    media: "(prefers-reduced-motion: reduce)",
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  }) as MediaQueryList;

describe("useAnimatedCount", () => {
  it("updates immediately when reduced motion is enabled", () => {
    jest.spyOn(window, "matchMedia").mockReturnValue(createMediaQuery(true));

    const count = renderHook(({ target }) => useAnimatedCount(target), {
      initialProps: { target: 12 },
    });

    expect(count.result.current).toBe(12);
    count.rerender({ target: 24 });
    expect(count.result.current).toBe(24);
  });

  it("animates toward each new page total", () => {
    jest.useFakeTimers();
    jest.spyOn(window, "matchMedia").mockReturnValue(createMediaQuery(false));
    let timestamp = 0;
    jest.spyOn(performance, "now").mockImplementation(() => timestamp);
    jest
      .spyOn(window, "requestAnimationFrame")
      .mockImplementation((callback: FrameRequestCallback) => {
        return window.setTimeout(() => {
          timestamp += 160;
          callback(timestamp);
        }, 1);
      });
    jest
      .spyOn(window, "cancelAnimationFrame")
      .mockImplementation((handle: number) => window.clearTimeout(handle));

    try {
      const count = renderHook(({ target }) => useAnimatedCount(target), {
        initialProps: { target: 10 },
      });

      act(() => {
        jest.runAllTimers();
      });
      expect(count.result.current).toBe(10);

      count.rerender({ target: 20 });
      act(() => {
        jest.runAllTimers();
      });
      expect(count.result.current).toBe(20);
    } finally {
      jest.useRealTimers();
    }
  });
});

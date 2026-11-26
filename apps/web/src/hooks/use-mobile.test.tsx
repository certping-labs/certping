// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { act } from "react";
import { render, screen } from "@testing-library/react";

import { useIsMobile, useIsTabletScreen } from "@/hooks/use-mobile";

type Listener = (event?: { matches: boolean }) => void;

function createMatchMediaController(initialMatches: boolean) {
  let matches = initialMatches;
  const listeners = new Set<Listener>();

  const mediaQueryList = {
    matches,
    media: "",
    onchange: null,
    addEventListener: (_type: string, listener: Listener) => {
      listeners.add(listener);
    },
    removeEventListener: (_type: string, listener: Listener) => {
      listeners.delete(listener);
    },
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => true,
  } as unknown as MediaQueryList;

  return {
    setMatches(next: boolean) {
      matches = next;
      Object.defineProperty(mediaQueryList, "matches", {
        value: matches,
        configurable: true,
      });
      listeners.forEach((listener) => listener({ matches }));
    },
    factory: () => mediaQueryList,
  };
}

function Probe() {
  const mobile = useIsMobile();
  const tablet = useIsTabletScreen();
  return (
    <div>
      <div data-testid="mobile">{String(mobile)}</div>
      <div data-testid="tablet">{String(tablet)}</div>
    </div>
  );
}

describe("use-mobile hooks", () => {
  it("subscribes to matchMedia and updates on change", () => {
    const controller = createMatchMediaController(false);
    const original = window.matchMedia;
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: controller.factory,
    });

    render(<Probe />);
    expect(screen.getByTestId("mobile")).toHaveTextContent("false");
    expect(screen.getByTestId("tablet")).toHaveTextContent("false");

    act(() => {
      controller.setMatches(true);
    });
    expect(screen.getByTestId("mobile")).toHaveTextContent("true");
    expect(screen.getByTestId("tablet")).toHaveTextContent("true");

    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: original,
    });
  });
});

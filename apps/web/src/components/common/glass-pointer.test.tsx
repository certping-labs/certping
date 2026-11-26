// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { fireEvent, render } from "@testing-library/react";

import { GlassPointer } from "@/components/common/glass-pointer";

function mockMedia(matches: Record<string, boolean>) {
  window.matchMedia = jest.fn((query: string) => ({
    addEventListener: jest.fn(),
    addListener: jest.fn(),
    dispatchEvent: jest.fn(),
    matches: matches[query] ?? false,
    media: query,
    onchange: null,
    removeEventListener: jest.fn(),
    removeListener: jest.fn(),
  })) as unknown as typeof window.matchMedia;
}

function renderGlass() {
  const utils = render(
    <>
      <GlassPointer />
      <button className="lg lg-interactive" type="button">
        <span>Glass</span>
      </button>
      <button type="button">Plain</button>
    </>,
  );
  const glass = utils.getByRole("button", { name: "Glass" });
  glass.getBoundingClientRect = () =>
    ({ left: 10, top: 20 }) as unknown as DOMRect;
  return { ...utils, glass };
}

beforeEach(() => {
  jest.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
    callback(0);
    return 1;
  });
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe("GlassPointer", () => {
  it("moves the highlight to the pointer on interactive glass", () => {
    mockMedia({ "(hover: hover) and (pointer: fine)": true });
    const { glass, getByRole } = renderGlass();

    fireEvent.pointerMove(getByRole("button", { name: "Glass" }).firstChild!, {
      clientX: 60,
      clientY: 45,
    });

    expect(glass.style.getPropertyValue("--lg-x")).toBe("50px");
    expect(glass.style.getPropertyValue("--lg-y")).toBe("25px");

    fireEvent.pointerMove(getByRole("button", { name: "Plain" }), {
      clientX: 5,
      clientY: 5,
    });
    expect(glass.style.getPropertyValue("--lg-x")).toBe("50px");
  });

  it("stays off for touch screens and reduced motion", () => {
    mockMedia({
      "(hover: hover) and (pointer: fine)": true,
      "(prefers-reduced-motion: reduce)": true,
    });
    const { glass } = renderGlass();

    fireEvent.pointerMove(glass, { clientX: 60, clientY: 45 });

    expect(glass.style.getPropertyValue("--lg-x")).toBe("");
  });
});

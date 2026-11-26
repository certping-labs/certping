// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { useRef } from "react";
import { act, render, screen } from "@testing-library/react";

import { useActiveChildThumb } from "@/hooks/use-sliding-thumb";

const ITEM_WIDTH = 100;

function Harness({ items, active }: { items: string[]; active: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const { moving, thumbStyle } = useActiveChildThumb(ref);
  return (
    <div ref={ref} data-testid="list">
      <span
        aria-hidden
        data-testid="thumb"
        data-moving={moving}
        style={thumbStyle}
      />
      {items.map((item, index) => (
        <button
          key={item}
          type="button"
          data-left={index * ITEM_WIDTH}
          data-state={item === active ? "active" : "inactive"}
        >
          {item}
        </button>
      ))}
    </div>
  );
}

const flushObservers = () => act(() => Promise.resolve());

describe("useActiveChildThumb", () => {
  const observed = new Set<Element>();
  const descriptors = new Map<string, PropertyDescriptor | undefined>();

  beforeEach(() => {
    observed.clear();
    const layout: Record<string, (el: HTMLElement) => number> = {
      offsetLeft: (el) => Number(el.dataset.left ?? 0),
      offsetWidth: () => ITEM_WIDTH,
      clientWidth: () => 4 * ITEM_WIDTH,
    };
    for (const [name, get] of Object.entries(layout)) {
      descriptors.set(
        name,
        Object.getOwnPropertyDescriptor(HTMLElement.prototype, name),
      );
      Object.defineProperty(HTMLElement.prototype, name, {
        configurable: true,
        get() {
          return get(this as HTMLElement);
        },
      });
    }
    global.ResizeObserver = class {
      observe(element: Element) {
        observed.add(element);
      }
      unobserve() {}
      disconnect() {
        observed.clear();
      }
    } as unknown as typeof ResizeObserver;
  });

  afterEach(() => {
    for (const [name, descriptor] of descriptors) {
      if (descriptor) {
        Object.defineProperty(HTMLElement.prototype, name, descriptor);
      } else {
        delete (HTMLElement.prototype as unknown as Record<string, unknown>)[
          name
        ];
      }
    }
    // @ts-expect-error jsdom has no ResizeObserver of its own.
    delete global.ResizeObserver;
  });

  it("watches every item's size but not the thumb, including items added later", async () => {
    const { rerender } = render(<Harness items={["a", "b"]} active="a" />);

    expect(observed).toContain(screen.getByTestId("list"));
    expect(observed).toContain(screen.getByRole("button", { name: "b" }));
    expect(observed).not.toContain(screen.getByTestId("thumb"));

    rerender(<Harness items={["a", "b", "c"]} active="a" />);
    await flushObservers();

    expect(observed).toContain(screen.getByRole("button", { name: "c" }));
    expect(observed).not.toContain(screen.getByTestId("thumb"));
  });

  it("settles without sliding when content moves, and slides on a new selection", async () => {
    const { rerender } = render(<Harness items={["b", "c"]} active="c" />);
    const thumb = screen.getByTestId("thumb");
    expect(thumb.style.left).toBe("100px");

    rerender(<Harness items={["a", "b", "c"]} active="c" />);
    await flushObservers();

    expect(thumb.style.left).toBe("200px");
    expect(thumb.dataset.moving).toBe("false");

    rerender(<Harness items={["a", "b", "c"]} active="a" />);
    await flushObservers();

    expect(thumb.style.left).toBe("0px");
    expect(thumb.dataset.moving).toBe("true");
  });
});

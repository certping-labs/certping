// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import "@testing-library/jest-dom";

// Radix UI + user-event compatibility shims for JSDOM.
if (typeof window !== "undefined") {
  // JSDOM does not implement real navigation; some code paths try to redirect
  // by assigning to window.location.href. Stub navigation methods to keep tests
  // deterministic.
  try {
    const originalLocation = window.location;
    const mutableWindow = window as unknown as { location?: Location };
    delete mutableWindow.location;
    Object.defineProperty(window, "location", {
      value: {
        ...originalLocation,
        assign: jest.fn(),
        replace: jest.fn(),
        reload: jest.fn(),
        href: originalLocation.href,
        pathname: originalLocation.pathname,
      },
      configurable: true,
      writable: true,
    });
  } catch {
    // Ignore if the runtime disallows location reassignment.
  }

  if (!window.matchMedia) {
    window.matchMedia = ((query: string) =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as MediaQueryList) as typeof window.matchMedia;
  }

  if (!HTMLElement.prototype.scrollIntoView) {
    HTMLElement.prototype.scrollIntoView = () => {};
  }

  if (!window.PointerEvent) {
    // Radix relies on PointerEvent for interactions; JSDOM may not provide it.
    window.PointerEvent = window.MouseEvent as unknown as typeof PointerEvent;
  }

  if (!window.IntersectionObserver) {
    class TestIntersectionObserver implements IntersectionObserver {
      readonly root = null;
      readonly rootMargin = "0px";
      readonly thresholds = [0];

      disconnect() {}

      observe() {}

      takeRecords(): IntersectionObserverEntry[] {
        return [];
      }

      unobserve() {}
    }

    window.IntersectionObserver = TestIntersectionObserver;
    globalThis.IntersectionObserver = TestIntersectionObserver;
  }

  if (!window.ResizeObserver) {
    // cmdk and Radix popper measure their content; JSDOM has no layout to observe.
    class TestResizeObserver implements ResizeObserver {
      disconnect() {}

      observe() {}

      unobserve() {}
    }

    window.ResizeObserver = TestResizeObserver;
    globalThis.ResizeObserver = TestResizeObserver;
  }

  const elementPrototype = Element.prototype as unknown as {
    hasPointerCapture?: (pointerId: number) => boolean;
    setPointerCapture?: (pointerId: number) => void;
    releasePointerCapture?: (pointerId: number) => void;
  };

  elementPrototype.hasPointerCapture ??= () => false;
  elementPrototype.setPointerCapture ??= () => {};
  elementPrototype.releasePointerCapture ??= () => {};
}

const storageFactory = (): Storage => {
  const store = new Map<string, string>();

  return {
    get length() {
      return store.size;
    },
    clear: () => {
      store.clear();
    },
    getItem: (key: string) => (store.has(key) ? store.get(key)! : null),
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    removeItem: (key: string) => {
      store.delete(key);
    },
    setItem: (key: string, value: string) => {
      store.set(key, String(value));
    },
  };
};

if (typeof window !== "undefined") {
  Object.defineProperty(window, "localStorage", {
    value: storageFactory(),
    configurable: true,
  });

  Object.defineProperty(window, "sessionStorage", {
    value: storageFactory(),
    configurable: true,
  });
}

const mswRuntimeReady =
  typeof globalThis.fetch !== "undefined" &&
  typeof globalThis.Request !== "undefined" &&
  typeof globalThis.Response !== "undefined" &&
  typeof globalThis.Headers !== "undefined";

if (mswRuntimeReady && process.env.ENABLE_MSW_TEST_SERVER === "true") {
  const { server } = require("@/test/msw/server") as {
    server: {
      listen: (options?: {
        onUnhandledFrame?: "error" | "warn" | "bypass";
      }) => void;
      resetHandlers: () => void;
      close: () => void;
    };
  };

  beforeAll(() => {
    server.listen({ onUnhandledFrame: "error" });
  });

  afterEach(() => {
    server.resetHandlers();
  });

  afterAll(() => {
    server.close();
  });
}

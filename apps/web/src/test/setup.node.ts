// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

if (!process.env.NEXT_PUBLIC_API_URL) {
  process.env.NEXT_PUBLIC_API_URL = "https://example-app-api.local";
}

process.env.ENABLE_MSW_TEST_SERVER ??= "true";

const utilRuntime = require("util") as {
  TextEncoder: typeof globalThis.TextEncoder;
  TextDecoder: typeof globalThis.TextDecoder;
};
const UtilTextEncoder = utilRuntime.TextEncoder;
const UtilTextDecoder = utilRuntime.TextDecoder;
const {
  ReadableStream: NodeReadableStream,
  WritableStream: NodeWritableStream,
  TransformStream: NodeTransformStream,
} = require("stream/web") as {
  ReadableStream: typeof globalThis.ReadableStream;
  WritableStream: typeof globalThis.WritableStream;
  TransformStream: typeof globalThis.TransformStream;
};

class MockBroadcastChannel {
  name: string;
  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(name: string) {
    this.name = name;
  }

  postMessage(message: unknown): void {
    void message;
  }

  close(): void {}

  addEventListener(): void {}

  removeEventListener(): void {}
}

if (typeof globalThis.TextEncoder === "undefined") {
  Object.defineProperty(globalThis, "TextEncoder", {
    value: UtilTextEncoder,
    configurable: true,
  });
}

if (typeof globalThis.TextDecoder === "undefined") {
  Object.defineProperty(globalThis, "TextDecoder", {
    value: UtilTextDecoder,
    configurable: true,
  });
}

if (typeof globalThis.ReadableStream === "undefined") {
  Object.defineProperty(globalThis, "ReadableStream", {
    value: NodeReadableStream,
    configurable: true,
  });
}

if (typeof globalThis.WritableStream === "undefined") {
  Object.defineProperty(globalThis, "WritableStream", {
    value: NodeWritableStream,
    configurable: true,
  });
}

if (typeof globalThis.TransformStream === "undefined") {
  Object.defineProperty(globalThis, "TransformStream", {
    value: NodeTransformStream,
    configurable: true,
  });
}

if (typeof globalThis.BroadcastChannel === "undefined") {
  Object.defineProperty(globalThis, "BroadcastChannel", {
    value: MockBroadcastChannel,
    configurable: true,
  });
}

const FIXED_NOW = new Date("2026-01-01T00:00:00.000Z").valueOf();

Date.now = () => FIXED_NOW;

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: {},
    configurable: true,
  });
}

if (!globalThis.crypto.randomUUID) {
  Object.defineProperty(globalThis.crypto, "randomUUID", {
    value: () => "00000000-0000-4000-8000-000000000000",
    configurable: true,
  });
}

const edgeRuntimeFetch =
  require("next/dist/compiled/@edge-runtime/primitives/fetch") as {
    fetch?: typeof fetch;
    Request?: typeof Request;
    Response?: typeof Response;
    Headers?: typeof Headers;
    FormData?: typeof FormData;
  };

if (typeof globalThis.fetch === "undefined" && edgeRuntimeFetch.fetch) {
  Object.defineProperty(globalThis, "fetch", {
    value: edgeRuntimeFetch.fetch,
    configurable: true,
  });
}

if (typeof globalThis.Request === "undefined" && edgeRuntimeFetch.Request) {
  Object.defineProperty(globalThis, "Request", {
    value: edgeRuntimeFetch.Request,
    configurable: true,
  });
}

if (typeof globalThis.Response === "undefined" && edgeRuntimeFetch.Response) {
  Object.defineProperty(globalThis, "Response", {
    value: edgeRuntimeFetch.Response,
    configurable: true,
  });
}

if (typeof globalThis.Headers === "undefined" && edgeRuntimeFetch.Headers) {
  Object.defineProperty(globalThis, "Headers", {
    value: edgeRuntimeFetch.Headers,
    configurable: true,
  });
}

if (typeof globalThis.FormData === "undefined" && edgeRuntimeFetch.FormData) {
  Object.defineProperty(globalThis, "FormData", {
    value: edgeRuntimeFetch.FormData,
    configurable: true,
  });
}

// Unrelated component tests run as if every feature were confirmed on. This
// stub is NOT the gating contract: suites that test gating must
// `jest.unmock("@/hooks/use-feature-flags")` (or `jest.requireActual`) and
// drive the real `useFeatureFlagStore` - see feature-route-gate tests.
jest.mock("@/hooks/use-feature-flags", () => ({
  FEATURE_FLAGS_QUERY_PREFIX: ["feature-flags"],
  featureFlagsQueryKey: (organizationId?: string | null) => [
    "feature-flags",
    "effective",
    organizationId ?? null,
  ],
  useFeatureFlagsSync: () => undefined,
  useFeatureFlags: () => ({
    status: "ready",
    availabilityOf: () => "on",
    isEnabled: () => true,
    isReady: true,
  }),
  useFeatureAvailability: () => "on",
  useIsFeatureEnabled: () => true,
  useIsOrgFeatureEnabled: () => true,
  useIsRouteAvailable: () => () => true,
  useRetryFeatureFlags: () => ({ retry: () => undefined, isRetrying: false }),
}));

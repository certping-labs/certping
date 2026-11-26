/** @jest-environment node */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { registerNodeTelemetry } from "./instrumentation-node";
import { register } from "./instrumentation";

jest.mock("./instrumentation-node", () => ({
  registerNodeTelemetry: jest.fn(),
}));

const originalNextRuntime = process.env.NEXT_RUNTIME;

afterEach(() => {
  if (originalNextRuntime === undefined) {
    delete process.env.NEXT_RUNTIME;
  } else {
    process.env.NEXT_RUNTIME = originalNextRuntime;
  }
});

it("registers telemetry in the Node.js runtime", async () => {
  process.env.NEXT_RUNTIME = "nodejs";

  await register();

  expect(registerNodeTelemetry).toHaveBeenCalledTimes(1);
});

it("does not load Node.js telemetry in the edge runtime", async () => {
  process.env.NEXT_RUNTIME = "edge";

  await register();

  expect(registerNodeTelemetry).not.toHaveBeenCalled();
});

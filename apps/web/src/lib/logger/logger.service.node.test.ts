/** @jest-environment node */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { emitOtelLog } from "./otel-log.service";

jest.mock("./otel-log.service", () => ({ emitOtelLog: jest.fn() }));

describe("server logger", () => {
  it("writes to stdout and emits an OTel log record", async () => {
    const infoSpy = jest.spyOn(console, "info").mockImplementation(() => {});
    const { logger } = await import("./logger.service");

    await logger.info("server event", { requestId: "request-123" });

    expect(infoSpy).toHaveBeenCalledWith("[INFO] server event", {
      requestId: "request-123",
    });
    expect(emitOtelLog).toHaveBeenCalledWith(
      expect.objectContaining({
        level: "info",
        message: "server event",
        meta: { requestId: "request-123" },
      }),
      "server",
    );
  });
});

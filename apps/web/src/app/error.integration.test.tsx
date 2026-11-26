// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, waitFor } from "@testing-library/react";

import GlobalError from "@/app/error";
import { logger } from "@/lib/logger/logger.service";

jest.mock("@/lib/logger/logger.service", () => ({
  logger: {
    error: jest.fn().mockResolvedValue(undefined),
  },
}));

describe("global error boundary logging", () => {
  it("emits detailed logger event when page crashes", async () => {
    const reset = jest.fn();
    const error = Object.assign(new Error("UI exploded"), {
      digest: "err-123",
    });

    render(<GlobalError error={error} reset={reset} />);

    await waitFor(() => {
      expect(logger.error).toHaveBeenCalledWith(
        "Global error boundary captured an app crash",
        expect.objectContaining({
          eventName: "exception",
          error,
          digest: "err-123",
        }),
      );
    });
  });
});

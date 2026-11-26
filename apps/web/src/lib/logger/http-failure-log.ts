// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";

import { logger } from "@/lib/logger/logger.service";

const EXPECTED_TRANSIENT_STATUSES = new Set([408, 429]);

/** Logs operationally useful HTTP failures while avoiding routine client errors. */
export function logHttpClientFailure(error: unknown): boolean {
  if (!axios.isAxiosError(error) || error.code === "ERR_CANCELED") {
    return false;
  }

  const metadata = {
    eventName: "http.client.request.exception",
    error,
  };
  const status = error.response?.status;
  if (status === undefined) {
    void logger.warn(
      "Backend request failed before a response was received",
      metadata,
    );
    return true;
  }
  if (status >= 500) {
    void logger.error("Backend request returned a server error", metadata);
    return true;
  }
  if (EXPECTED_TRANSIENT_STATUSES.has(status)) {
    void logger.warn("Backend request was throttled or timed out", metadata);
    return true;
  }
  return false;
}

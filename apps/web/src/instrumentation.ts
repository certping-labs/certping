// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/** Registers server-side telemetry before Next.js starts handling requests. */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== "nodejs") {
    return;
  }

  const { registerNodeTelemetry } = await import("./instrumentation-node");
  registerNodeTelemetry();
}

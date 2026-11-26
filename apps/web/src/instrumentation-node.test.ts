/** @jest-environment node */

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { BatchLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { registerOTel } from "@vercel/otel";

import { registerNodeTelemetry } from "./instrumentation-node";

jest.mock("@opentelemetry/exporter-logs-otlp-http", () => ({
  OTLPLogExporter: jest.fn(),
}));
jest.mock("@opentelemetry/exporter-metrics-otlp-http", () => ({
  OTLPMetricExporter: jest.fn(),
}));
jest.mock("@opentelemetry/sdk-logs", () => ({
  BatchLogRecordProcessor: jest.fn(),
}));
jest.mock("@opentelemetry/sdk-metrics", () => ({
  PeriodicExportingMetricReader: jest.fn(),
}));
jest.mock("@vercel/otel", () => ({ registerOTel: jest.fn() }));

const OTEL_VARIABLES = [
  "OTEL_EXPORTER_OTLP_ENDPOINT",
  "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
  "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
  "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
  "OTEL_TRACES_EXPORTER",
  "OTEL_METRICS_EXPORTER",
  "OTEL_LOGS_EXPORTER",
  "OTEL_SERVICE_NAME",
  "OTEL_SDK_DISABLED",
] as const;

const originalEnvironment = Object.fromEntries(
  OTEL_VARIABLES.map((variableName) => [
    variableName,
    process.env[variableName],
  ]),
);

afterEach(() => {
  for (const variableName of OTEL_VARIABLES) {
    const originalValue = originalEnvironment[variableName];
    if (originalValue === undefined) {
      delete process.env[variableName];
    } else {
      process.env[variableName] = originalValue;
    }
  }
});

it("configures trace, metric, and log OTLP providers", () => {
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://collector:4318";
  process.env.OTEL_SERVICE_NAME = "test-pki-app";

  registerNodeTelemetry();

  expect(OTLPLogExporter).toHaveBeenCalledTimes(1);
  expect(BatchLogRecordProcessor).toHaveBeenCalledTimes(1);
  expect(OTLPMetricExporter).toHaveBeenCalledTimes(1);
  expect(PeriodicExportingMetricReader).toHaveBeenCalledTimes(1);
  expect(registerOTel).toHaveBeenCalledWith(
    expect.objectContaining({
      serviceName: "test-pki-app",
      spanProcessors: ["auto"],
      logRecordProcessors: [expect.anything()],
      metricReaders: [expect.anything()],
    }),
  );
});

it("honors disabled signal exporters", () => {
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://collector:4318";
  process.env.OTEL_TRACES_EXPORTER = "none";
  process.env.OTEL_METRICS_EXPORTER = "none";
  process.env.OTEL_LOGS_EXPORTER = "none";

  registerNodeTelemetry();

  expect(registerOTel).toHaveBeenCalledWith(
    expect.objectContaining({
      serviceName: "certping-pki-app",
      spanProcessors: [],
      logRecordProcessors: [],
      metricReaders: [],
    }),
  );
});

it("does not initialize an unconfigured or disabled SDK", () => {
  registerNodeTelemetry();
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = "http://collector:4318";
  process.env.OTEL_SDK_DISABLED = "TRUE";
  registerNodeTelemetry();

  expect(registerOTel).not.toHaveBeenCalled();
});

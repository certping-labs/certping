// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-http";
import { BatchLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { registerOTel } from "@vercel/otel";

const DEFAULT_SERVICE_NAME = "certping-pki-app";

function isExporterEnabled(variableName: string): boolean {
  const configuredExporters = process.env[variableName]
    ?.split(",")
    .map((exporter) => exporter.trim().toLowerCase());

  return !configuredExporters || configuredExporters.includes("otlp");
}

function isTelemetryDisabled(): boolean {
  return process.env.OTEL_SDK_DISABLED?.toLowerCase() === "true";
}

function isTelemetryConfigured(): boolean {
  return [
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_TRACES_EXPORTER",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
  ].some((variableName) => Boolean(process.env[variableName]));
}

/** Configures the Node.js OTel providers using the standard OTEL_* environment variables. */
export function registerNodeTelemetry(): void {
  if (isTelemetryDisabled() || !isTelemetryConfigured()) {
    return;
  }

  const areTracesEnabled = isExporterEnabled("OTEL_TRACES_EXPORTER");
  const areLogsEnabled = isExporterEnabled("OTEL_LOGS_EXPORTER");
  const areMetricsEnabled = isExporterEnabled("OTEL_METRICS_EXPORTER");

  registerOTel({
    serviceName: process.env.OTEL_SERVICE_NAME ?? DEFAULT_SERVICE_NAME,
    spanProcessors: areTracesEnabled ? ["auto"] : [],
    logRecordProcessors: areLogsEnabled
      ? [
          new BatchLogRecordProcessor({
            exporter: new OTLPLogExporter(),
          }),
        ]
      : [],
    metricReaders: areMetricsEnabled
      ? [
          new PeriodicExportingMetricReader({
            exporter: new OTLPMetricExporter(),
          }),
        ]
      : [],
  });
}

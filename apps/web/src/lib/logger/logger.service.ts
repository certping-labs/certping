// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { LogMessage } from "@/types";

import { CORRELATION_ID_HEADER } from "@/lib/correlation-id";
import { CLIENT_LOG_PATH } from "@/lib/logger/client-log-path";
import { createLogMessage } from "@/lib/logger/log-context";
import { emitOtelLog } from "@/lib/logger/otel-log.service";

class Logger {
  private static instance: Logger;
  private readonly isServer: boolean;

  private constructor() {
    this.isServer = typeof window === "undefined";
  }

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  private consoleLog(logData: LogMessage): void {
    const { eventName, level, message, meta } = logData;
    const consoleMethod = level === "debug" ? "log" : level;
    const context = {
      ...(eventName ? { "event.name": eventName } : {}),
      ...(meta ?? {}),
    };
    console[consoleMethod](`[${level.toUpperCase()}] ${message}`, context);
  }

  private async sendToAPI(logData: LogMessage): Promise<void> {
    try {
      const correlationId = logData.meta?.["correlation.id"];
      const response = await fetch(CLIENT_LOG_PATH, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(typeof correlationId === "string"
            ? { [CORRELATION_ID_HEADER]: correlationId }
            : {}),
        },
        body: JSON.stringify(logData),
        keepalive: true,
      });
      if (!response.ok) {
        console.warn("Logger API rejected log", {
          status: response.status,
          level: logData.level,
        });
      }
    } catch (error) {
      console.error("Failed to send log to API:", error);
    }
  }

  async log(
    level: LogMessage["level"],
    message: string,
    meta?: Record<string, unknown>,
  ): Promise<void> {
    const logData = createLogMessage(level, message, meta);

    this.consoleLog(logData);

    if (this.isServer) {
      emitOtelLog(logData, "server");
    } else {
      await this.sendToAPI(logData);
    }
  }

  debug(message: string, meta?: Record<string, unknown>) {
    return this.log("debug", message, meta);
  }

  info(message: string, meta?: Record<string, unknown>) {
    return this.log("info", message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>) {
    return this.log("warn", message, meta);
  }

  error(message: string, meta?: Record<string, unknown>) {
    return this.log("error", message, meta);
  }
}

export const logger = Logger.getInstance();

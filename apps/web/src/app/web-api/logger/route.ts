// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { NextRequest, NextResponse } from "next/server";

import {
  ClientLogRequestError,
  readClientLogMessage,
} from "@/app/web-api/logger/client-log-request";
import { emitOtelLog } from "@/lib/logger/otel-log.service";

export async function POST(request: NextRequest) {
  try {
    const logData = await readClientLogMessage(request);

    const formattedMessage = `[client:${logData.level}] ${logData.message}`;
    const structuredData = {
      source: "client",
      level: logData.level,
      "event.name": logData.eventName,
      timestamp: logData.timestamp,
      meta: logData.meta,
    };

    if (logData.level === "debug") {
      console.log(formattedMessage, structuredData);
    } else {
      console[logData.level](formattedMessage, structuredData);
    }
    emitOtelLog(logData, "client");

    return NextResponse.json(
      { success: true },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (error) {
    if (error instanceof ClientLogRequestError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.status, headers: { "Cache-Control": "no-store" } },
      );
    }
    console.error("Logging error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 },
    );
  }
}

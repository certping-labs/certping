// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export interface IAlert {
  action_type: string;
  website_details: {
    url: string;
    alias: string;
  };
  alert_details: {
    status: number;
    down_timestamp: string;
    failure_reason: string;
  };
  created_at: string;
  severity: string;
  message: string;
}

export interface LogMessage {
  level: "debug" | "info" | "warn" | "error";
  message: string;
  eventName?: string;
  meta?: Record<string, unknown>;
  timestamp?: string;
}

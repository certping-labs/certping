// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { format, isValid, parseISO } from "date-fns";
import { Dispatch, SetStateAction } from "react";
import { jwtDecode, JwtPayload } from "jwt-decode";
import { logger } from "./logger/logger.service";
import { ZodError } from "zod";
import { AxiosError } from "axios";
import { errorReference, withReference } from "@/lib/correlation-id";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function normalizeUrl(url: string): string {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = `https://${url}`;
  }
  return url.trim();
}

export function decodeJWT<T>(payload: string | null) {
  try {
    if (!payload || payload === null) return null;
    const data = jwtDecode(payload) as JwtPayload & T;
    return data;
  } catch (err) {
    logger.error("JWT decoding failed", {
      eventName: "auth.jwt_decode.exception",
      error: err,
    });
    return null;
  }
}

export const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;

export interface PasswordError {
  message: string;
  checks: {
    length: boolean;
    uppercase: boolean;
    lowercase: boolean;
    number: boolean;
    special: boolean;
  };
}

export const AUTH_URLS = ["/login", "/setup"];

export const validatePasswordStrenght = ({
  setError,
  value,
}: {
  value: string;
  setError: Dispatch<SetStateAction<PasswordError | null>>;
}) => {
  const checks = {
    length: value.length >= 12,
    uppercase: /[A-Z]/.test(value),
    lowercase: /[a-z]/.test(value),
    number: /\d/.test(value),
    special: /[^A-Za-z0-9]/.test(value),
  };
  if (!value) {
    setError(null);
    return true;
  }
  const isValid = PASSWORD_REGEX.test(value);

  if (!isValid) {
    setError({
      message: "Password must meet all requirements",
      checks,
    });
  } else {
    setError(null);
  }

  return isValid;
};

export function getDaysFromTimeRange(timeRange: string): number {
  switch (timeRange) {
    case "90d":
      return 90;
    case "30d":
      return 30;
    case "7d":
      return 7;
    default:
      return 7;
  }
}

export function formatZodErrors(error?: ZodError) {
  if (!error) return null;

  const formattedErrors: Record<string, string> = {};

  error.errors.forEach((err) => {
    if (err.path.length > 0) {
      const path = err.path.join(".");
      formattedErrors[path] = err.message;
    }
  });

  if (Object.keys(formattedErrors).length === 0) {
    return error.errors.map((e) => e.message).join(", ");
  }

  return formattedErrors;
}

export function getRootDomain(domain: string = ""): string {
  const parts = domain.split(".");
  if (parts.length > 2) {
    return parts.slice(-2).join(".");
  }
  return domain;
}

export function formatDate(dateString: string | null): string {
  const date = parseDateValue(dateString);
  if (!date) return "-";
  return format(date, "MMM d, yyyy");
}

// Helper to check UTC dates or NOT
function hasTimezone(value: string): boolean {
  return /(?:Z|[+-]\d{2}:?\d{2})$/i.test(value);
}

export function formatDateTimeCompact(dateString: string | null): string {
  const date = parseDateValue(dateString);
  if (!date) return "-";
  return format(date, "MMM d, yyyy, h:mm a");
}

export function formatDateTimeWithSeconds(
  dateString: string | null | undefined,
): string {
  const date = parseDateValue(dateString);
  if (!date) return "-";
  return format(date, "MMM d, yyyy, h:mm:ss a");
}

export function formatDateTimeDetailed(
  dateString: string | null | undefined,
): string {
  const date = parseDateValue(dateString);
  if (!date) return "-";
  return format(date, "EEEE, MMM d, yyyy 'at' h:mm a");
}

export const formatDateTime = formatDateTimeCompact;

export function getRemainingDays(validTo: string | null): number | null {
  const expiryDate = parseDateValue(validTo);
  if (!expiryDate) {
    return null;
  }

  const diffTime = expiryDate.getTime() - Date.now();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
}

export function getValidFrom(cert: {
  validFrom?: string | null;
  valid_from?: string | null;
}): string | null {
  return cert.validFrom || cert.valid_from || null;
}

export function getValidTo(cert: {
  validTo?: string | null;
  valid_to?: string | null;
}): string | null {
  return cert.validTo || cert.valid_to || null;
}

export function getCreatedAt(cert: {
  createdAt?: string | null;
  created_at?: string | null;
}): string | null {
  return cert.createdAt || cert.created_at || null;
}

export function getUpdatedAt(cert: {
  updatedAt?: string | null;
  updated_at?: string | null;
}): string | null {
  return cert.updatedAt || cert.updated_at || null;
}

export function formatCertDate(dateString: string | null | undefined): string {
  const formatted = formatDate(dateString ?? null);
  return formatted === "-" ? "N/A" : formatted;
}

export function formatCertDateTime(
  dateString: string | null | undefined,
): string {
  const formatted = formatDateTime(dateString ?? null);
  return formatted === "-" ? "N/A" : formatted;
}

export function parseDateValue(
  dateString: string | null | undefined,
): Date | null {
  if (!dateString) {
    return null;
  }
  const normalized = hasTimezone(dateString) ? dateString : `${dateString}Z`; // assume UTC when timezone is missing
  const date = parseISO(normalized);
  if (!isValid(date)) {
    return null;
  }

  return date;
}

export function getExpiryLabel(
  validTo: string | null | undefined,
  options: {
    warningThresholdDays?: number;
    expiredLabel?: string;
    pendingLabel?: string;
  } = {},
): {
  tone: "default" | "warning" | "critical";
  text: string;
} {
  const {
    warningThresholdDays = 30,
    expiredLabel = "Expired",
    pendingLabel = "Awaiting issuance",
  } = options;

  const remainingDays = getRemainingDays(validTo ?? null);
  if (remainingDays === null) {
    return {
      tone: "default",
      text: pendingLabel,
    };
  }

  if (remainingDays <= 0) {
    return {
      tone: "critical",
      text: expiredLabel,
    };
  }

  if (remainingDays <= warningThresholdDays) {
    return {
      tone: "critical",
      text: `Expiring in ${remainingDays} day${remainingDays === 1 ? "" : "s"}`,
    };
  }

  return {
    tone: "default",
    text: `${remainingDays} day${remainingDays === 1 ? "" : "s"} remaining`,
  };
}

export function getSSLStatusBadge(
  status: string,
): "success" | "destructive" | "warning" | "default" {
  switch (status.toUpperCase()) {
    case "ACTIVE":
    case "ISSUED":
      return "success";
    case "EXPIRED":
      return "destructive";
    case "REVOKED":
      return "destructive";
    case "FAILED":
      return "destructive";
    case "PENDING":
    case "PENDING_DNS":
    case "VALIDATING":
    case "AWAITING_DNS":
    case "RENEWING":
    case "REVOKING":
      return "warning";
    default:
      return "default";
  }
}

export function copyToClipboard(text: string): void {
  navigator.clipboard.writeText(text).catch((err) => {
    console.error("Could not copy text: ", err);
  });
}

export const sanitizeDomain = (input: string) => {
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
    const url = new URL(hasScheme ? input : `http://${input}`);

    return url.hostname;
  } catch {
    throw new Error("Invalid domain format");
  }
};

export const getErrorMessage = (error: unknown, fallback: string): string => {
  if (error instanceof AxiosError) {
    const payload = error.response?.data as
      { error?: string; message?: string; detail?: string } | undefined;
    return withReference(
      payload?.message ||
        payload?.error ||
        payload?.detail ||
        error.message ||
        fallback,
      errorReference(error),
    );
  }
  if (error instanceof Error) {
    return withReference(error.message, errorReference(error));
  }
  return fallback;
};

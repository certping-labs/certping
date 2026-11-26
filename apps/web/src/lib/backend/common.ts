// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";
import { z } from "zod";

export interface ApiFieldError {
  field?: string;
  message?: string;
  rejectedValue?: unknown;
}

export interface ApiErrorDetail {
  code?: string;
  message?: string;
  retryAfterSeconds?: number;
}

export interface ApiErrorResponse {
  status?: number;
  error?: string | ApiErrorDetail;
  message?: string;
  path?: string;
  timestamp?: string;
  fieldErrors?: ApiFieldError[];
}

const apiErrorDetailSchema = z
  .object({
    code: z.string().optional(),
    message: z.string().optional(),
    retryAfterSeconds: z.number().optional(),
  })
  .passthrough();

const apiErrorPayloadSchema = z
  .object({
    status: z.number().optional(),
    error: z.union([z.string(), apiErrorDetailSchema]).optional(),
    message: z.string().optional(),
    detail: z.string().optional(),
    title: z.string().optional(),
    path: z.string().optional(),
    timestamp: z.string().optional(),
    data: z.unknown().optional(),
    fieldErrors: z
      .array(
        z.object({
          field: z.string().optional(),
          message: z.string().optional(),
          rejectedValue: z.unknown().optional(),
        }),
      )
      .optional(),
  })
  .passthrough();

const parseApiErrorPayload = (value: unknown) => {
  const result = apiErrorPayloadSchema.safeParse(value);
  return result.success ? result.data : undefined;
};

const extractErrorMessage = (value: unknown): string | undefined => {
  if (typeof value === "string") {
    return value.trim() || undefined;
  }

  const payload = parseApiErrorPayload(value);
  if (!payload) {
    return undefined;
  }

  const errorMessage =
    typeof payload.error === "string" ? payload.error : payload.error?.message;
  const message =
    payload.message ?? errorMessage ?? payload.detail ?? payload.title;
  if (message?.trim()) {
    return message.trim();
  }

  return payload.data === value ? undefined : extractErrorMessage(payload.data);
};

/** The message the API's error body carries; null for any other error or a body without one. */
export const getApiResponseMessage = (error: unknown): string | null => {
  if (!axios.isAxiosError(error)) {
    return null;
  }
  const responseData = error.response?.data;
  const fieldMessage = parseApiErrorPayload(responseData)?.fieldErrors?.find(
    (fieldError) => fieldError.message,
  )?.message;
  return fieldMessage ?? extractErrorMessage(responseData) ?? null;
};

export const getApiErrorMessage = (
  error: unknown,
  fallback: string,
): string => {
  if (axios.isAxiosError(error)) {
    return getApiResponseMessage(error) ?? error.message ?? fallback;
  }

  return error instanceof Error ? error.message : fallback;
};

/**
 * A `responseType: "blob"` request receives its error body as a Blob, which
 * hides the JSON message from `getApiErrorMessage`. Replaces the Blob with the
 * parsed body and rethrows so callers see what the API returned.
 */
export const rethrowWithDecodedBlobError = async (
  error: unknown,
): Promise<never> => {
  if (
    axios.isAxiosError(error) &&
    error.response?.data instanceof Blob &&
    typeof error.response.data.text === "function"
  ) {
    const text = await error.response.data.text().catch(() => "");
    try {
      error.response.data = text ? JSON.parse(text) : undefined;
    } catch {
      error.response.data = undefined;
    }
  }
  throw error;
};

/** Every field error in an API error's body; none for any other error. */
export const getApiFieldErrors = (error: unknown): ApiFieldError[] =>
  axios.isAxiosError(error)
    ? (parseApiErrorPayload(error.response?.data)?.fieldErrors ?? [])
    : [];

export const getApiFieldErrorMessage = (
  error: unknown,
  fieldName: string,
): string | null =>
  getApiFieldErrors(error).find((fieldError) => fieldError.field === fieldName)
    ?.message ?? null;

export const isUuid = (value: string | undefined): boolean =>
  Boolean(
    value &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    ),
  );

/** The machine-readable `code` of an API error's body; null when it has none. */
export const getApiErrorCode = (error: unknown): string | null => {
  if (!axios.isAxiosError(error)) {
    return null;
  }
  const payload = parseApiErrorPayload(error.response?.data);
  const code =
    typeof payload?.error === "object" ? payload.error.code : payload?.code;
  return typeof code === "string" && code !== "" ? code : null;
};

/** How long an API error asks the caller to wait before retrying; null when it does not say. */
export const getApiRetryAfterSeconds = (error: unknown): number | null => {
  if (!axios.isAxiosError(error)) {
    return null;
  }
  const detail = parseApiErrorPayload(error.response?.data)?.error;
  const seconds = typeof detail === "object" ? detail.retryAfterSeconds : null;
  return typeof seconds === "number" && seconds > 0 ? Math.ceil(seconds) : null;
};

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import axios from "axios";

import { loadPage } from "@/lib/browser-navigation";
import { logger } from "@/lib/logger/logger.service";
import { type SignedOutReason, getLoginPath } from "@/lib/signed-out-reason";
import { AUTH_URLS } from "@/lib/utils";
import {
  AUTH_STORAGE_KEY,
  LEGACY_AUTH_STORAGE_KEY,
  useAuthStore,
} from "@/stores/auth-store";

// The server answers an inactive user or organization with these exact 401 messages, in
// `error` (token filter) or `message` (error handler). A token refresh cannot cure them.
const REASON_BY_REFUSAL = new Map<string, SignedOutReason>([
  ["Account is disabled or deleted", "account-disabled"],
  ["Organization is suspended or inactive", "organization-suspended"],
]);

function reasonForRefusal(text: unknown): SignedOutReason | null {
  return typeof text === "string"
    ? (REASON_BY_REFUSAL.get(text) ?? null)
    : null;
}

function getSignedOutReason(body: unknown): SignedOutReason | null {
  if (typeof body !== "object" || body === null) return null;
  const { message, error } = body as { message?: unknown; error?: unknown };
  return reasonForRefusal(message) ?? reasonForRefusal(error);
}

// Parallel requests can end the session again without a reason, and the auth provider
// redirects once the store is reset; neither may drop the reason the page is leaving for.
export function getPendingSignedOutReason(): SignedOutReason | undefined {
  return useAuthStore.getState().signedOutReason ?? undefined;
}

/** Why an error refuses the account itself, or null when a fresh token might still help. */
export function getAccountRefusal(error: unknown): SignedOutReason | null {
  if (!axios.isAxiosError(error) || error.response?.status !== 401) {
    return null;
  }
  return getSignedOutReason(error.response.data);
}

/** Clears the stored session and sends the browser to sign-in, saying why when the reason is known. */
export function endSession(reason?: SignedOutReason | null): void {
  logger.warn("Authentication failed, clearing tokens", {
    eventName: "auth.session_invalidated",
    reason,
  });
  if (typeof window === "undefined") return;
  try {
    const leavingPage = !AUTH_URLS.includes(window.location.pathname);
    const signedOutReason = leavingPage
      ? (reason ?? getPendingSignedOutReason())
      : undefined;
    if (leavingPage) loadPage(getLoginPath(signedOutReason));
    useAuthStore.getState().logout();
    useAuthStore.setState({ signedOutReason: signedOutReason ?? null });
    localStorage.removeItem(AUTH_STORAGE_KEY);
    localStorage.removeItem(LEGACY_AUTH_STORAGE_KEY);
  } catch (error) {
    logger.error("Error during auth failure cleanup", {
      eventName: "auth.session_cleanup.exception",
      error,
    });
  }
}

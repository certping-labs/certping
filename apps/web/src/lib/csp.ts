// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Content Security Policy for every page. Scripts run only with the per-request nonce that
 * src/proxy.ts generates ('strict-dynamic' lets those scripts load Next's chunks), so an
 * injected inline or third-party script does not execute. Styles keep 'unsafe-inline' because
 * Radix, sonner and the top loader set inline styles; style-src must not carry a nonce, or
 * browsers ignore 'unsafe-inline'.
 */

export interface CspOptions {
  nonce: string;
  /** Development adds 'unsafe-eval' (React dev tooling) and websocket for hot reload. */
  isDev?: boolean;
  /** NEXT_PUBLIC_API_URL. When it is an absolute URL its origin joins connect-src. */
  apiUrl?: string;
}

/** The origin of an absolute http(s) API URL, or null for relative and `same-origin` values. */
export function apiOrigin(apiUrl?: string): string | null {
  const value = apiUrl?.trim();
  if (!value || !/^https?:\/\//i.test(value)) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

export function buildContentSecurityPolicy({
  nonce,
  isDev = false,
  apiUrl,
}: CspOptions): string {
  const api = apiOrigin(apiUrl);
  const directives: Record<string, string[]> = {
    "default-src": ["'self'"],
    "script-src": [
      "'self'",
      `'nonce-${nonce}'`,
      "'strict-dynamic'",
      ...(isDev ? ["'unsafe-eval'"] : []),
    ],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'", "data:"],
    "connect-src": [
      "'self'",
      ...(api ? [api] : []),
      ...(isDev ? ["ws:", "wss:"] : []),
    ],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    // The SSO start is a link, not a form, and the identity provider answers the server.
    "form-action": ["'self'"],
    "object-src": ["'none'"],
  };
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
}

/** 128 random bits, base64. Works in the Node and edge runtimes. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

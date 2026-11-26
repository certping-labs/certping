// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Value of NEXT_PUBLIC_API_URL meaning "the API is on the same origin as the web app", which is
 * how the self-hosted images are built: Caddy or an Ingress routes /api to the server, so one
 * image works for every domain without a rebuild.
 */
export const SAME_ORIGIN = "same-origin";

/**
 * Base URL for API calls. NEXT_PUBLIC_API_URL is inlined at build time; `same-origin` resolves to
 * the page's origin in the browser and to CERTPING_URL, the public URL read at runtime, on the
 * Next.js server, so server and browser render the same links. With nothing configured the
 * fallback (empty by default) makes API paths relative to the page, never a vendor host.
 */
export function apiBaseUrl(fallback: string = ""): string {
  const configured = process.env.NEXT_PUBLIC_API_URL;
  if (configured && configured !== SAME_ORIGIN) {
    return configured;
  }
  if (configured === SAME_ORIGIN) {
    if (typeof window !== "undefined" && window.location?.origin) {
      return window.location.origin;
    }
    return process.env.CERTPING_URL ?? "http://localhost";
  }
  return fallback;
}

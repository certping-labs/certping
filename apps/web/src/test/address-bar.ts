// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Puts jsdom's address bar on `href` and watches the history, so a test can read what a reload
 * would open and tell a replaced entry from an added one.
 */
export function trackAddressBar(
  href = "http://localhost/domain/registrations",
) {
  window.history.replaceState(null, "", href);
  const replaceState = jest.spyOn(window.history, "replaceState");
  const pushState = jest.spyOn(window.history, "pushState");
  return {
    replaceState,
    pushState,
    /** The address bar's query, as a reload would read it. */
    params: () => new URL(window.location.href).searchParams,
  };
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/** A full page load, which drops every in-memory store; a seam that tests replace. */
export function loadPage(path: string): void {
  window.location.href = path;
}

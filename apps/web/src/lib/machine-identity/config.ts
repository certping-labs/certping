// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/** Tunables shared by the Machine Identity adapters, hooks, and pages. */
export const MACHINE_IDENTITY_CONFIG = {
  list: {
    defaultPageSize: 25,
    maxPageSize: 200,
    staleTimeMs: 30_000,
  },
  detail: {
    staleTimeMs: 60_000,
  },
  overview: {
    staleTimeMs: 60_000,
  },
  /**
   * Refresh cadences.
   *
   * <p>Nothing in this module is driven from the UI. Device certificates are
   * issued when a device runs SCEP against the CA, devices appear when the
   * hourly source sync lands, and source and CA health arrive as agent
   * messages - so a screen left open goes stale with no local signal that
   * anything happened, and the operator's only recourse was a reload.
   *
   * <p>Three speeds rather than one, because the cost of polling is paid by
   * the backend on every focused tab:
   */
  polling: {
    /**
     * Something is demonstrably in flight and its progress is on screen: a
     * sync run, a profile push waiting on the provider, an enrollment that has
     * not completed.
     */
    activeMs: 5_000,
    /**
     * The backend changes this on its own and the operator is looking at it -
     * inventories, detail pages, activity feeds.
     */
    liveMs: 60_000,
    /**
     * Supporting aggregates and health summaries, where being a couple of
     * minutes behind changes no decision.
     */
    ambientMs: 180_000,
    /**
     * Stop chasing a run that never reaches a terminal state, so one wedged
     * sync cannot poll for the lifetime of the tab.
     */
    maxActiveMs: 5 * 60_000,
  },
} as const;

/** Page-size choices offered on Machine Identity tables. */
export const MACHINE_IDENTITY_PAGE_SIZES = [10, 25, 50, 100] as const;

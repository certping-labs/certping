// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { create } from "zustand";

export type NetworkFailureSource = "api" | "browser";

interface NetworkIssue {
  detectedAt: number;
  message: string;
  source: NetworkFailureSource;
}

interface NetworkStatusState {
  issue: NetworkIssue | null;
  clearNetworkIssue: () => void;
  reportNetworkIssue: (message?: string, source?: NetworkFailureSource) => void;
}

export const DEFAULT_NETWORK_ERROR_MESSAGE = "Live data request failed.";

export const useNetworkStatusStore = create<NetworkStatusState>((set) => ({
  issue: null,
  clearNetworkIssue: () => set({ issue: null }),
  reportNetworkIssue: (
    message = DEFAULT_NETWORK_ERROR_MESSAGE,
    source = "api",
  ) =>
    set({
      issue: {
        detectedAt: Date.now(),
        message,
        source,
      },
    }),
}));

export const reportApiNetworkIssue = (message?: string): void => {
  useNetworkStatusStore.getState().reportNetworkIssue(message, "api");
};

export const clearNetworkIssue = (): void => {
  useNetworkStatusStore.getState().clearNetworkIssue();
};

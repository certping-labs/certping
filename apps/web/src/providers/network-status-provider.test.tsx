// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { act, render, screen } from "@testing-library/react";

import { useNetworkStatusStore } from "@/lib/network-status";
import { NetworkStatusProvider } from "@/providers/network-status-provider";

describe("NetworkStatusProvider", () => {
  beforeEach(() => {
    useNetworkStatusStore.getState().clearNetworkIssue();
  });

  it("renders children when the network is healthy", () => {
    render(
      <NetworkStatusProvider>
        <div>Console content</div>
      </NetworkStatusProvider>,
    );

    expect(screen.getByText("Console content")).toBeInTheDocument();
  });

  it("keeps rendering children when an API network issue is reported", () => {
    act(() => {
      useNetworkStatusStore
        .getState()
        .reportNetworkIssue("Live data could not be refreshed.", "api");
    });

    render(
      <NetworkStatusProvider>
        <div>Console content</div>
      </NetworkStatusProvider>,
    );

    expect(screen.getByText("Console content")).toBeInTheDocument();
  });

  it("reports browser offline events without replacing the console", () => {
    render(
      <NetworkStatusProvider>
        <div>Console content</div>
      </NetworkStatusProvider>,
    );

    act(() => {
      window.dispatchEvent(new Event("offline"));
    });

    expect(screen.getByText("Console content")).toBeInTheDocument();
    expect(useNetworkStatusStore.getState().issue?.source).toBe("browser");

    act(() => {
      window.dispatchEvent(new Event("online"));
    });

    expect(screen.getByText("Console content")).toBeInTheDocument();
    expect(useNetworkStatusStore.getState().issue).toBeNull();
  });

  it("keeps API issue state when the tab regains focus online", () => {
    act(() => {
      useNetworkStatusStore
        .getState()
        .reportNetworkIssue("Live data could not be refreshed.", "api");
    });

    render(
      <NetworkStatusProvider>
        <div>Console content</div>
      </NetworkStatusProvider>,
    );

    expect(screen.getByText("Console content")).toBeInTheDocument();

    act(() => {
      window.dispatchEvent(new Event("focus"));
    });

    expect(screen.getByText("Console content")).toBeInTheDocument();
    expect(useNetworkStatusStore.getState().issue?.source).toBe("api");
  });

  it("clears browser offline state when the tab regains focus online without replacing the console", () => {
    act(() => {
      useNetworkStatusStore
        .getState()
        .reportNetworkIssue("Browser connection restored.", "browser");
    });

    render(
      <NetworkStatusProvider>
        <div>Console content</div>
      </NetworkStatusProvider>,
    );

    expect(screen.getByText("Console content")).toBeInTheDocument();
    expect(useNetworkStatusStore.getState().issue?.source).toBe("browser");

    act(() => {
      window.dispatchEvent(new Event("focus"));
    });

    expect(screen.getByText("Console content")).toBeInTheDocument();
  });
});

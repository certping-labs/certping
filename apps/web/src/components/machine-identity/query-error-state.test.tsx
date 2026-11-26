// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError, AxiosHeaders } from "axios";

import { MachineIdentityQueryErrorState } from "@/components/machine-identity/query-error-state";

function apiError(status: number, data?: Record<string, unknown>): AxiosError {
  const error = new AxiosError("Request failed");
  error.response = {
    status,
    statusText: "",
    data: data ?? {},
    headers: new AxiosHeaders(),
    config: { headers: new AxiosHeaders() },
  };
  return error;
}

const BASE_PROPS = {
  title: "Unable to load devices",
  description: "The device inventory could not be loaded.",
};

describe("MachineIdentityQueryErrorState", () => {
  it("names the disabled capability from the 423 body rather than the page", () => {
    render(
      <MachineIdentityQueryErrorState
        {...BASE_PROPS}
        error={apiError(423, {
          status: 423,
          feature: "IOT_CERTIFICATE_PROFILE_MANAGEMENT",
        })}
      />,
    );

    // The shared not-available surface, not a pointer at a setting the org
    // admin may not be able to switch.
    expect(
      screen.getByRole("heading", {
        name: "Certificate profiles isn't available",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/ask your CertPing administrator/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /feature settings/i }),
    ).not.toBeInTheDocument();
  });

  it("separates an expired session from a missing permission", () => {
    const { unmount } = render(
      <MachineIdentityQueryErrorState {...BASE_PROPS} error={apiError(401)} />,
    );
    expect(screen.getByText("Your session has expired")).toBeInTheDocument();
    unmount();

    render(
      <MachineIdentityQueryErrorState {...BASE_PROPS} error={apiError(403)} />,
    );
    expect(screen.getByText("You do not have access")).toBeInTheDocument();
  });

  it("only says a record is gone when the API actually said so", () => {
    render(
      <MachineIdentityQueryErrorState
        {...BASE_PROPS}
        error={apiError(404)}
        resourceLabel="device"
        backHref="/machine-identity/devices"
        backLabel="Back to devices"
      />,
    );

    expect(
      screen.getByText("This device no longer exists"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to devices" }),
    ).toHaveAttribute("href", "/machine-identity/devices");
  });

  it("treats a server fault as transient and offers a retry", async () => {
    const onRetry = jest.fn();
    render(
      <MachineIdentityQueryErrorState
        {...BASE_PROPS}
        error={apiError(500)}
        onRetry={onRetry}
      />,
    );

    expect(screen.getByText("Unable to load devices")).toBeInTheDocument();
    expect(screen.getByText(/usually clears on its own/i)).toBeInTheDocument();
    expect(screen.getByText("HTTP 500")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("reports a request that never reached the API as a connectivity problem", () => {
    render(
      <MachineIdentityQueryErrorState
        {...BASE_PROPS}
        error={new AxiosError("Network Error")}
        onRetry={jest.fn()}
      />,
    );

    expect(
      screen.getByText("CertPing could not be reached"),
    ).toBeInTheDocument();
  });

  it("reads a successful query with nothing to show as a missing record", () => {
    // The device-source detail page has no single-source GET: it finds its
    // record in the cached list, so "loaded fine, not in the list" is the
    // only signal that the source is gone.
    render(
      <MachineIdentityQueryErrorState
        {...BASE_PROPS}
        error={undefined}
        resourceLabel="device source"
      />,
    );

    expect(
      screen.getByText("This device source no longer exists"),
    ).toBeInTheDocument();
  });

  it("hides the retry action when the caller cannot retry", () => {
    render(
      <MachineIdentityQueryErrorState {...BASE_PROPS} error={apiError(500)} />,
    );

    expect(
      screen.queryByRole("button", { name: /try again/i }),
    ).not.toBeInTheDocument();
  });
});

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";

import { SomethingWentWrong } from "@/components/common/error";

describe("SomethingWentWrong", () => {
  it("renders provided title and description", () => {
    render(
      <SomethingWentWrong title="Load failed" description="Try again later." />,
    );

    expect(
      screen.getByRole("heading", { name: /load failed/i }),
    ).toBeInTheDocument();
    expect(screen.getByText("Try again later.")).toBeInTheDocument();
  });

  it("falls back to default title when missing", () => {
    render(<SomethingWentWrong description="Try again later." />);

    expect(
      screen.getByRole("heading", { name: "Something went wrong" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Try again" }),
    ).not.toBeInTheDocument();
  });

  it("offers a retry and the support reference when given", () => {
    const onRetry = jest.fn();
    render(
      <SomethingWentWrong
        description="The service did not respond."
        reference="req-123"
        onRetry={onRetry}
      />,
    );

    expect(screen.getByText("req-123")).toBeInTheDocument();
    expect(screen.getByText(/Reference:/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});

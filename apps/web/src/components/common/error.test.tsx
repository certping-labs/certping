// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";

import { SomethingWentWrong } from "@/components/common/error";

describe("SomethingWentWrong", () => {
  it("renders provided title and description", () => {
    render(
      <SomethingWentWrong title="Failed to load" description="Try again" />,
    );
    expect(screen.getByText("Failed to load")).toBeInTheDocument();
    expect(screen.getByText("Try again")).toBeInTheDocument();
  });

  it("falls back to default title when title is nullish", () => {
    render(
      <SomethingWentWrong
        title={undefined as unknown as string}
        description="Oops"
      />,
    );
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
  });
});

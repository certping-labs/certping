// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";

import { AuditRetentionCard } from "@/components/settings/audit/audit-retention-card";
import { auditRetentionFixture } from "@/test/fixtures/audit-retention";
import { server } from "@/test/msw/server";

jest.mock("@/components/ui/select", () =>
  jest.requireActual("@/test/select-mock"),
);

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: { id: "root" },
    isLoading: false,
    isSuperAdmin: true,
  }),
}));

const RETENTION_URL = `${process.env.NEXT_PUBLIC_API_URL}/api/v1/admin/settings/audit-retention`;

describe("audit retention period on a phone", () => {
  it("offers the same choices as a select below sm, and segments from sm up, with no sideways scroll", async () => {
    server.use(
      http.get(RETENTION_URL, () => HttpResponse.json(auditRetentionFixture())),
    );
    render(
      <QueryClientProvider client={new QueryClient()}>
        <AuditRetentionCard />
      </QueryClientProvider>,
    );

    const select = await screen.findByTestId("retention-choice-select");
    const segments = screen.getByTestId("retention-choice-segments");
    expect(select).toHaveClass("sm:hidden");
    expect(segments).toHaveClass("hidden", "sm:block");
    expect(segments.outerHTML).not.toContain("overflow-x-auto");

    await userEvent.setup().click(within(select).getByText("Custom"));
    expect(
      within(segments).getByRole("button", { name: "Custom" }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("spinbutton", { name: "Months" })).toHaveValue(
      null,
    );
  });
});

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";

import {
  applyRotationFilter,
  RotationPage,
  toRotationRows,
} from "@/components/cert-manager/rotation/rotation-page";
import type { SSLCertificateListItem } from "@/types/ssl";

const mutate = jest.fn();
let permissions: string[] = ["certificate:read", "certificate:renew"];
let listState: { data?: SSLCertificateListItem[]; isLoading: boolean } = {
  data: [],
  isLoading: false,
};

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "u1",
      organizationId: "7",
      roles: ["SECURITY_ANALYST"],
      permissions,
    },
    isLoading: false,
  }),
}));
jest.mock("@/hooks/ssl", () => ({
  useListCertificates: () => listState,
  useRenewCertificate: () => ({ mutate, isPending: false }),
}));
jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({ title }: { title: string }) => <h1>{title}</h1>,
}));

const DAY = 86_400_000;
const now = new Date("2026-10-25T12:00:00Z");
const inDays = (d: number) => new Date(now.getTime() + d * DAY).toISOString();

const certs: SSLCertificateListItem[] = [
  {
    certificateXref: "a",
    domain: "a.example.com",
    status: "ACTIVE",
    validTo: inDays(10),
    managementState: "fully-managed",
    caProvider: "LETS_ENCRYPT",
  },
  {
    certificateXref: "b",
    domain: "b.example.com",
    status: "RENEWAL_FAILED",
    validTo: inDays(5),
    managementState: "dns-managed",
    caProvider: "DIGICERT",
  },
  {
    certificateXref: "c",
    domain: "c.example.com",
    status: "ACTIVE",
    validTo: inDays(80),
    managementState: "manual",
  },
  {
    certificateXref: "d",
    domain: "d.example.com",
    status: "REVOKED",
    validTo: inDays(80),
  },
  {
    certificateXref: "e",
    domain: "e.example.com",
    status: "RENEWING",
    validTo: inDays(2),
    managementState: "fully-managed",
  },
];

describe("rotation rows", () => {
  it("drops revoked certificates, puts failures first, then soonest expiry", () => {
    const rows = toRotationRows(certs, now);
    expect(rows.map((r) => r.certificate.domain)).toEqual([
      "b.example.com",
      "e.example.com",
      "a.example.com",
      "c.example.com",
    ]);
    expect(rows[0]).toMatchObject({
      failed: true,
      dueSoon: true,
      automated: true,
    });
    expect(rows[3]).toMatchObject({
      automated: false,
      dueSoon: false,
      daysLeft: 80,
    });
  });

  it("filters by due, failed and manual", () => {
    const rows = toRotationRows(certs, now);
    expect(
      applyRotationFilter(rows, "due").map((r) => r.certificate.domain),
    ).toEqual(["b.example.com", "e.example.com", "a.example.com"]);
    expect(applyRotationFilter(rows, "failed")).toHaveLength(1);
    expect(
      applyRotationFilter(rows, "manual").map((r) => r.certificate.domain),
    ).toEqual(["c.example.com"]);
  });
});

describe("RotationPage", () => {
  beforeEach(() => {
    mutate.mockReset();
    permissions = ["certificate:read", "certificate:renew"];
    listState = { data: certs, isLoading: false };
  });

  it("shows the counts, the connection links and Renew now for an analyst", () => {
    render(<RotationPage />);

    expect(screen.getByText("3 of 4")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Certificate authorities" }),
    ).toHaveAttribute("href", "/integrations/certificate-authorities");
    expect(screen.getByRole("link", { name: "DNS providers" })).toHaveAttribute(
      "href",
      "/integrations/dns",
    );

    const table = screen.getByRole("table");
    const renewButtons = within(table).getAllByRole("button", {
      name: "Renew now",
    });
    // a, b and c are renewable; e is already renewing.
    expect(renewButtons).toHaveLength(3);
    fireEvent.click(renewButtons[0]);
    expect(mutate).toHaveBeenCalledWith({ certificateXref: "b" });
  });

  it("filters the schedule to failed renewals", () => {
    render(<RotationPage />);

    fireEvent.click(screen.getByRole("button", { name: "Failed" }));
    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(rows).toHaveLength(2); // header and b
    expect(rows[1]).toHaveTextContent("b.example.com");
    expect(rows[1]).toHaveTextContent("Last renewal failed");
  });

  it("offers no Renew now to a viewer", () => {
    permissions = ["certificate:read"];
    render(<RotationPage />);
    expect(
      screen.queryByRole("button", { name: "Renew now" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("a.example.com")).toBeInTheDocument();
  });

  it("explains the empty state", () => {
    listState = { data: [], isLoading: false };
    render(<RotationPage />);
    expect(screen.getByText(/No certificates yet/)).toBeInTheDocument();
  });
});

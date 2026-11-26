// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";

import { DeleteOrganizationDialog } from "@/components/settings/organizations/organization-dialogs";
import { OrganizationCard } from "@/components/settings/organizations/organization-table";
import type { Organization } from "@/types/auth";

jest.mock("@/lib/auth-ui-mode", () => ({
  ...jest.requireActual("@/lib/auth-ui-mode"),
  isEnterpriseAppMode: () => true,
}));

const renderDialog = (onDelete = jest.fn(), onOpenChange = jest.fn()) => {
  render(
    <DeleteOrganizationDialog
      open
      canDelete
      organization={{ organizationId: "7", organizationName: "Acme Ltd" }}
      isPending={false}
      onOpenChange={onOpenChange}
      onDelete={onDelete}
    />,
  );
  return { onDelete, onOpenChange };
};

describe("DeleteOrganizationDialog", () => {
  it("names the organization and deletes on confirm", () => {
    const { onDelete } = renderDialog();

    expect(
      screen.getByText(
        "Delete Acme Ltd? Members lose access immediately, and its certificates, integrations and settings are removed. This action cannot be undone.",
      ),
    ).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Delete organization" }),
    );

    expect(onDelete).toHaveBeenCalledTimes(1);
  });

  it("closes without deleting on cancel", () => {
    const { onDelete, onOpenChange } = renderDialog();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onDelete).not.toHaveBeenCalled();
  });
});

describe("OrganizationCard", () => {
  const organization = {
    organizationId: "7",
    name: "Acme Ltd",
    slug: "acme",
    domain: "acme.example",
    active: true,
  } as unknown as Organization;

  it("shows the organization's name, domain and status", () => {
    render(
      <OrganizationCard
        organization={organization}
        canUpdate
        canDelete
        onView={jest.fn()}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );

    expect(screen.getByText("Acme Ltd")).toBeInTheDocument();
    expect(screen.getByText("acme.example")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
  });
});

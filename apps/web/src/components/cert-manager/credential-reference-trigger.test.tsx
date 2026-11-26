// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React, { type ComponentProps } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CredentialReferenceTrigger } from "@/components/cert-manager/credential-reference-trigger";
import { CredentialDetailsDialog } from "@/components/cert-manager/credential-details-dialog";
import { useCredentials } from "@/hooks/credentials";
import { useAuthStore } from "@/stores/auth-store";
import type { CredentialRecord } from "@/types/ssl";

const pushMock = jest.fn();
let mockDnsCredentialsEnabled = true;
let mockIntegrationsAvailable = true;

jest.mock("@/hooks/use-feature-flags", () => ({
  useIsFeatureEnabled: (key: string) =>
    key !== "DNS_CREDENTIALS" || mockDnsCredentialsEnabled,
  useIsRouteAvailable: () => (href: string) =>
    !href.startsWith("/integrations/") || mockIntegrationsAvailable,
}));

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

jest.mock("@/hooks/credentials", () => ({
  useCredentials: jest.fn(),
}));

jest.mock("@/components/cert-manager/credential-details-dialog", () => ({
  CredentialDetailsDialog: (
    props: ComponentProps<typeof CredentialDetailsDialog>,
  ) =>
    props.open ? (
      <div role="dialog" aria-label="Credential details">
        <span>{props.credential?.credentialXref}</span>
        {props.onEdit && props.credential ? (
          <button
            type="button"
            onClick={() => {
              if (props.credential) {
                props.onEdit?.(props.credential);
              }
            }}
          >
            Update credential
          </button>
        ) : null}
        {props.onDelete ? <button type="button">Delete</button> : null}
      </div>
    ) : null,
}));

const credential: CredentialRecord = {
  id: 1,
  alias: "cred-1",
  credentialXref: "cred-1",
  description: "Production credential",
  credentialType: "cloudflare",
  type: "DNS",
  provider: "cloudflare",
  providerName: "CLOUDFLARE",
  metadata: {},
  createdAt: "2026-06-24T00:00:00.000Z",
  updatedAt: "2026-06-24T00:00:00.000Z",
  nextRotationAt: "2026-09-22T00:00:00.000Z",
  rotationInterval: 90,
  version: 1,
  status: "ACTIVE",
};

describe("CredentialReferenceTrigger", () => {
  beforeEach(() => {
    pushMock.mockReset();
    mockDnsCredentialsEnabled = true;
    mockIntegrationsAvailable = true;
    jest.mocked(useCredentials).mockReturnValue({
      data: [credential],
      isLoading: false,
      isFetching: false,
    } as ReturnType<typeof useCredentials>);
    useAuthStore.setState({
      user: {
        id: "user-1",
        email: "user@example.com",
        organizationId: "org-1",
        organizationName: "Org",
        roles: ["USER"],
        permissions: ["credential:read", "credential:rotate"],
        authMethod: "LOCAL",
      },
      expiresAt: Date.now() + 60_000,
      isLoading: false,
      isSuperAdmin: false,
    });
  });

  it("opens details in place and navigates only from the update action", async () => {
    const user = userEvent.setup();
    render(<CredentialReferenceTrigger credentialXref="cred-1" />);

    await user.click(
      screen.getByRole("button", { name: "View credential cred-1" }),
    );

    expect(
      screen.getByRole("dialog", { name: "Credential details" }),
    ).toBeInTheDocument();
    expect(pushMock).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Delete" }),
    ).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Update credential" }));

    expect(pushMock).toHaveBeenCalledWith(
      "/integrations/connections/cred-1/edit",
    );
  });

  it("offers no update while the credential pages are off", async () => {
    mockIntegrationsAvailable = false;
    const user = userEvent.setup();
    render(<CredentialReferenceTrigger credentialXref="cred-1" />);

    await user.click(
      screen.getByRole("button", { name: "View credential cred-1" }),
    );

    expect(
      screen.getByRole("dialog", { name: "Credential details" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Update credential" }),
    ).not.toBeInTheDocument();
  });

  it("offers no update for a DNS credential while DNS credentials are off", async () => {
    mockDnsCredentialsEnabled = false;
    const user = userEvent.setup();
    render(<CredentialReferenceTrigger credentialXref="cred-1" />);

    await user.click(
      screen.getByRole("button", { name: "View credential cred-1" }),
    );

    expect(
      screen.getByRole("dialog", { name: "Credential details" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Update credential" }),
    ).not.toBeInTheDocument();
  });

  it("still offers the update for a deployment credential while DNS credentials are off", async () => {
    mockDnsCredentialsEnabled = false;
    jest.mocked(useCredentials).mockReturnValue({
      data: [{ ...credential, type: "DEPLOYMENT" }],
      isLoading: false,
      isFetching: false,
    } as ReturnType<typeof useCredentials>);
    const user = userEvent.setup();
    render(<CredentialReferenceTrigger credentialXref="cred-1" />);

    await user.click(
      screen.getByRole("button", { name: "View credential cred-1" }),
    );

    expect(
      screen.getByRole("button", { name: "Update credential" }),
    ).toBeInTheDocument();
  });
});

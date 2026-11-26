// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CertificateReferenceSelect } from "@/components/cert-manager/certificate-reference-select";
import { useAuthStore } from "@/stores/auth-store";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import type { SsoUser } from "@/types/auth";
import type { SSLCertificateListItem } from "@/types/ssl";

// The issue option is flag-gated, so this suite drives the real flag store.
jest.unmock("@/hooks/use-feature-flags");

const pushMock = jest.fn();

const issuer: SsoUser = {
  id: "u1",
  email: "issuer@example.com",
  organizationId: "org-1",
  organizationName: "Org",
  roles: ["USER"],
  permissions: ["certificate:issue"],
  authMethod: "LOCAL",
} as SsoUser;

function setIssuance(enabled: boolean) {
  useFeatureFlagStore
    .getState()
    .setEffectiveMap({ CERTIFICATE_ISSUANCE: enabled });
}

jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

const certificate: SSLCertificateListItem = {
  certificateXref: "cert-active",
  domain: "certping.example",
  status: "ACTIVE",
};

describe("CertificateReferenceSelect", () => {
  beforeEach(() => {
    pushMock.mockReset();
    useAuthStore.setState({ user: issuer });
    setIssuance(true);
  });

  afterEach(() => {
    useFeatureFlagStore.getState().reset();
    useAuthStore.setState({ user: null });
  });

  it.each([
    ["issuance is off", () => setIssuance(false)],
    ["flags have not loaded", () => useFeatureFlagStore.getState().reset()],
    [
      "the user cannot issue",
      () => useAuthStore.setState({ user: { ...issuer, permissions: [] } }),
    ],
  ])("hides the issue action when %s", async (_scenario, arrange) => {
    arrange();
    const user = userEvent.setup();

    render(
      <CertificateReferenceSelect
        certificates={[certificate]}
        onValueChange={jest.fn()}
      />,
    );

    await user.click(screen.getByRole("combobox"));
    await screen.findByRole("option", { name: "certping.example" });
    expect(
      screen.queryByRole("option", { name: "Issue a certificate" }),
    ).not.toBeInTheDocument();
  });

  it.each([
    ["no certificates exist", []],
    ["certificates exist", [certificate]],
  ])("offers the issue action when %s", async (_scenario, certificates) => {
    const user = userEvent.setup();
    const onValueChange = jest.fn();

    render(
      <CertificateReferenceSelect
        certificates={certificates}
        onValueChange={onValueChange}
      />,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(
      await screen.findByRole("option", { name: "Issue a certificate" }),
    );

    expect(pushMock).toHaveBeenCalledWith("/cert-manager/add");
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it("selects an existing certificate without navigating", async () => {
    const user = userEvent.setup();
    const onValueChange = jest.fn();

    render(
      <CertificateReferenceSelect
        certificates={[certificate]}
        onValueChange={onValueChange}
      />,
    );

    await user.click(screen.getByRole("combobox"));
    await user.click(
      await screen.findByRole("option", { name: "certping.example" }),
    );

    expect(onValueChange).toHaveBeenCalledWith("cert-active");
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("exposes the trigger through its associated label", () => {
    const domainOnlyCertificate = { ...certificate, certificateXref: "" };

    render(
      <>
        <label htmlFor="certificate-reference">Certificate</label>
        <CertificateReferenceSelect
          id="certificate-reference"
          certificates={[domainOnlyCertificate]}
          onValueChange={jest.fn()}
        />
      </>,
    );

    expect(
      screen.getByRole("combobox", { name: "Certificate" }),
    ).toBeInTheDocument();
  });
});

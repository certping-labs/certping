// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ProfileForm } from "@/components/machine-identity/profile-form";
import { useCaConnectors } from "@/hooks/machine-identity/use-ca-connectors";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";

jest.mock("@/hooks/machine-identity/use-device-sources", () => ({
  useDeviceSources: jest.fn(),
}));
jest.mock("@/hooks/machine-identity/use-ca-connectors", () => ({
  useCaConnectors: jest.fn(),
}));
jest.mock("next/navigation", () => ({
  useRouter: () => ({ push: jest.fn() }),
}));

global.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as never;
Element.prototype.scrollIntoView = jest.fn();
Element.prototype.hasPointerCapture = jest.fn(() => false) as never;
Element.prototype.releasePointerCapture = jest.fn();

(useDeviceSources as jest.Mock).mockReturnValue({
  data: [{ sourceXref: "src-1", displayName: "Contoso Intune" }],
});
(useCaConnectors as jest.Mock).mockReturnValue({
  data: [{ connectorId: "conn-1", caProvider: "EJBCA" }],
});

async function selectDeviceSource(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("combobox", { name: "Device source" }));
  await user.click(screen.getByRole("option", { name: "Contoso Intune" }));
}

/**
 * Windows SCEP is the only native mutation the backend implements today, so
 * the form defaults to that target and the tests focus on the server-side
 * validation rules mirrored client-side for it.
 */
describe("ProfileForm", () => {
  it("defaults to a Windows SCEP profile and shows the compatibility notice", () => {
    render(
      <ProfileForm isSubmitting={false} onSubmit={jest.fn()} cancelHref="/x" />,
    );

    expect(
      screen.getByText("Windows SCEP validation applies"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Profile name")).toBeInTheDocument();
    expect(screen.getByText("Renewal threshold (%)")).toBeInTheDocument();
  });

  it("requires a device source before submitting", async () => {
    const onSubmit = jest.fn();
    const user = userEvent.setup();
    render(
      <ProfileForm isSubmitting={false} onSubmit={onSubmit} cancelHref="/x" />,
    );

    await user.type(screen.getByLabelText("Profile name"), "Test profile");
    await user.click(screen.getByRole("button", { name: "Create profile" }));

    await waitFor(() => {
      expect(screen.getByText("Select a device source")).toBeInTheDocument();
    });
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("rejects a description shaped like the reserved correlation marker", async () => {
    const user = userEvent.setup();
    render(
      <ProfileForm isSubmitting={false} onSubmit={jest.fn()} cancelHref="/x" />,
    );

    screen.getByLabelText("Description").focus();
    await user.paste("[certping:abc-123]");
    await user.click(screen.getByRole("button", { name: "Create profile" }));

    await waitFor(() => {
      expect(
        screen.getByText(
          /reserved for CertPing's internal correlation marker/i,
        ),
      ).toBeInTheDocument();
    });
  });

  it("rejects a malformed extended key usage OID", async () => {
    const user = userEvent.setup();
    render(
      <ProfileForm isSubmitting={false} onSubmit={jest.fn()} cancelHref="/x" />,
    );

    await user.click(
      screen
        .getAllByRole("button", { name: "Add" })
        .find((button) =>
          button.closest("div")?.textContent?.includes("Extended key usages"),
        ) as HTMLElement,
    );
    await user.type(
      screen.getByPlaceholderText("1.3.6.1.5.5.7.3.2"),
      "not-an-oid",
    );
    await user.click(screen.getByRole("button", { name: "Create profile" }));

    await waitFor(() => {
      expect(screen.getByText(/Must be a dotted OID/i)).toBeInTheDocument();
    });
  });

  it("submits a valid draft profile with confirmReissuance false", async () => {
    const onSubmit = jest.fn();
    const user = userEvent.setup();
    render(
      <ProfileForm isSubmitting={false} onSubmit={onSubmit} cancelHref="/x" />,
    );

    await user.type(screen.getByLabelText("Profile name"), "Test profile");
    await selectDeviceSource(user);
    await user.click(screen.getByRole("button", { name: "Create profile" }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    const [input, confirmReissuance] = onSubmit.mock.calls[0];
    expect(input).toMatchObject({
      name: "Test profile",
      sourceXref: "src-1",
      lifecycleStatus: "DRAFT",
      targetPlatform: "WINDOWS",
      profileKind: "CERTIFICATE_ENROLLMENT",
      enrollmentMethod: "SCEP",
    });
    expect(input.configuration).toMatchObject({
      keyAlgorithm: "RSA",
      keySize: 2048,
    });
    expect(confirmReissuance).toBe(false);
    expect(input.configuration.providerConfig).not.toHaveProperty(
      "assignmentGroupIds",
    );
  });

  it("sends Entra assignment groups as a deduplicated lower-case list", async () => {
    const onSubmit = jest.fn();
    const user = userEvent.setup();
    render(
      <ProfileForm isSubmitting={false} onSubmit={onSubmit} cancelHref="/x" />,
    );

    await user.type(screen.getByLabelText("Profile name"), "Test profile");
    await selectDeviceSource(user);
    screen.getByLabelText("Assign to Entra groups (object IDs)").focus();
    await user.paste(
      "8F6E0E4C-3C1A-4B8E-9D0F-2A1B3C4D5E6F\n8f6e0e4c-3c1a-4b8e-9d0f-2a1b3c4d5e6f, 1b2c3d4e-0000-4000-8000-000000000001",
    );
    await user.click(screen.getByRole("button", { name: "Create profile" }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(
      onSubmit.mock.calls[0][0].configuration.providerConfig.assignmentGroupIds,
    ).toEqual([
      "8f6e0e4c-3c1a-4b8e-9d0f-2a1b3c4d5e6f",
      "1b2c3d4e-0000-4000-8000-000000000001",
    ]);
  });

  it("rejects an assignment group that is not an object ID", async () => {
    const onSubmit = jest.fn();
    const user = userEvent.setup();
    render(
      <ProfileForm isSubmitting={false} onSubmit={onSubmit} cancelHref="/x" />,
    );

    await user.type(screen.getByLabelText("Profile name"), "Test profile");
    await selectDeviceSource(user);
    screen.getByLabelText("Assign to Entra groups (object IDs)").focus();
    await user.paste("All devices");
    await user.click(screen.getByRole("button", { name: "Create profile" }));

    await waitFor(() => {
      expect(
        screen.getByText(/Enter Entra group object IDs/i),
      ).toBeInTheDocument();
    });
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

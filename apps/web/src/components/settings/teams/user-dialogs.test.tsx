// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  InviteUserDialog,
  buildInviteUserSchema,
} from "@/components/settings/teams/user-dialogs";

const roleOptions = [{ value: "1", label: "Member" }];

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function renderInviteDialog(onCreate = jest.fn()) {
  render(
    <InviteUserDialog
      open
      canCreate
      isPending={false}
      roleOptions={roleOptions}
      onOpenChange={jest.fn()}
      onCreate={onCreate}
    />,
  );
}

describe("InviteUserDialog", () => {
  beforeAll(() => {
    global.ResizeObserver = ResizeObserverMock;
  });

  it("explains why username cannot be reused as the password", async () => {
    const user = userEvent.setup();
    const onCreate = jest.fn();
    renderInviteDialog(onCreate);

    await user.type(screen.getByLabelText("Username"), "Password123!");
    await user.type(screen.getByLabelText(/Email/i), "jane@example.com");
    await user.type(
      screen.getByPlaceholderText("Minimum 12 characters"),
      "Password123!",
    );
    await user.click(screen.getByRole("button", { name: "Add member" }));

    expect(
      await screen.findByText("Password cannot be the same as the username"),
    ).toBeInTheDocument();
    expect(onCreate).not.toHaveBeenCalled();
  });

  it("lets admins reveal and hide the generated password", async () => {
    const user = userEvent.setup();
    renderInviteDialog();

    const passwordInput = screen.getByPlaceholderText("Minimum 12 characters");
    expect(passwordInput).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(passwordInput).toHaveAttribute("type", "text");

    await user.click(screen.getByRole("button", { name: "Hide password" }));
    expect(passwordInput).toHaveAttribute("type", "password");
  });
});

describe("buildInviteUserSchema (conditional organization requirement)", () => {
  const SUPER_ADMIN_ROLE_ID = "99";
  const baseValues = {
    organizationId: "",
    displayName: "",
    username: "",
    email: "jane@example.com",
    roleIds: ["1"],
    password: "Sup3rSecret!Pass",
  };

  it("requires an organization when a super admin creates a non-super-admin member", () => {
    const schema = buildInviteUserSchema(true, [SUPER_ADMIN_ROLE_ID]);
    const result = schema.safeParse({ ...baseValues, roleIds: ["1"] });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(
        result.error.issues.some((issue) => issue.path[0] === "organizationId"),
      ).toBe(true);
    }
  });

  it("does NOT require an organization when the new member is a super admin", () => {
    const schema = buildInviteUserSchema(true, [SUPER_ADMIN_ROLE_ID]);
    const result = schema.safeParse({
      ...baseValues,
      roleIds: [SUPER_ADMIN_ROLE_ID],
    });
    expect(result.success).toBe(true);
  });

  it("still requires an organization when a super-admin role is configured but not selected", () => {
    const schema = buildInviteUserSchema(true, [SUPER_ADMIN_ROLE_ID]);
    const result = schema.safeParse({
      ...baseValues,
      roleIds: ["1", "2"],
    });
    expect(result.success).toBe(false);
  });

  it("does not require an organization for non-super-admin callers", () => {
    const schema = buildInviteUserSchema(false, [SUPER_ADMIN_ROLE_ID]);
    const result = schema.safeParse({ ...baseValues, roleIds: ["1"] });
    expect(result.success).toBe(true);
  });
});

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  EditUserDialog,
  type DirectGrantsState,
  type EditUserState,
} from "@/components/settings/teams/edit-user-dialog";

const roleOptions = [
  { value: "10", label: "Member" },
  { value: "11", label: "Operator" },
];
const rolePermissionsById = new Map<string, string[]>([
  ["10", ["certificate:view"]],
  ["11", ["certificate:view", "certificate:deploy"]],
]);
const permissionOptions = [
  { value: "certificate:view", label: "View certificates" },
  { value: "certificate:deploy", label: "Deploy certificates" },
  { value: "audit:view", label: "View audit log" },
];

const baseUser: EditUserState = {
  id: 42,
  displayName: "Jane Doe",
  email: "jane@acme.test",
  username: "jane",
  roleIds: ["10"],
  active: true,
};

function renderDialog({
  user = baseUser,
  directGrants = { status: "ready", permissionNames: [] },
  onSave = jest.fn(),
  onOpenChange = jest.fn(),
  isPending = false,
}: {
  user?: EditUserState | null;
  directGrants?: DirectGrantsState;
  isPending?: boolean;
  onSave?: jest.Mock;
  onOpenChange?: jest.Mock;
} = {}) {
  render(
    <EditUserDialog
      open
      user={user}
      directGrants={directGrants}
      isPending={isPending}
      roleOptions={roleOptions}
      rolePermissionsById={rolePermissionsById}
      permissionOptions={permissionOptions}
      onOpenChange={onOpenChange}
      onSave={onSave}
    />,
  );
  return { onSave, onOpenChange };
}

function comboboxFor(label: string) {
  const field = screen.getByText(label, { selector: "label" })
    .parentElement as HTMLElement;
  return within(field).getByRole("combobox");
}

describe("EditUserDialog", () => {
  beforeAll(() => {
    global.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  it("renders nothing without a member", () => {
    renderDialog({ user: null });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("holds the form until the member's direct grants have loaded", async () => {
    const user = userEvent.setup();
    const { onOpenChange } = renderDialog({
      directGrants: { status: "loading" },
    });

    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading member access",
    );
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    expect(screen.queryByLabelText("Display Name")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("closes without saving on cancel", async () => {
    const user = userEvent.setup();
    const { onOpenChange, onSave } = renderDialog();

    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onSave).not.toHaveBeenCalled();
  });

  it("disables saving while a save is in flight", () => {
    renderDialog({ isPending: true });

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("says when the selected roles grant nothing", () => {
    renderDialog({ user: { ...baseUser, roleIds: [] } });

    expect(
      screen.getByText("The selected roles don't grant any permissions."),
    ).toBeInTheDocument();
    expect(screen.getByText("0 permissions")).toBeInTheDocument();
  });

  it("shows each role permission with the roles that grant it", () => {
    renderDialog({ user: { ...baseUser, roleIds: ["10", "11"] } });

    const list = screen.getByRole("list", { name: "Permissions from roles" });
    const viewRow = within(list)
      .getByText("View certificates")
      .closest("li") as HTMLElement;
    expect(viewRow).toHaveTextContent("From Member, Operator");
    expect(within(viewRow).getByText("certificate:view")).toBeInTheDocument();
    expect(screen.getByText("2 permissions")).toBeInTheDocument();
  });

  it("drops an extra permission once a selected role covers it", async () => {
    const user = userEvent.setup();
    const { onSave } = renderDialog({
      directGrants: {
        status: "ready",
        permissionNames: ["certificate:deploy", "audit:view"],
      },
    });

    expect(comboboxFor("Additional permissions")).toHaveTextContent(
      "Deploy certificates",
    );

    await user.click(comboboxFor("Roles"));
    await user.click(await screen.findByRole("option", { name: "Operator" }));
    await user.keyboard("{Escape}");

    expect(comboboxFor("Additional permissions")).not.toHaveTextContent(
      "Deploy certificates",
    );
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith({
        displayName: "Jane Doe",
        username: "jane",
        email: "jane@acme.test",
        roleIds: ["10", "11"],
        extraPermissionNames: ["audit:view"],
      }),
    );
  });

  it("keeps an extra permission when the role that covered it is removed again", async () => {
    const user = userEvent.setup();
    const { onSave } = renderDialog({
      directGrants: {
        status: "ready",
        permissionNames: ["certificate:deploy", "audit:view"],
      },
    });

    await user.click(comboboxFor("Roles"));
    await user.click(await screen.findByRole("option", { name: "Operator" }));
    await user.click(await screen.findByRole("option", { name: "Operator" }));
    await user.keyboard("{Escape}");

    expect(comboboxFor("Additional permissions")).toHaveTextContent(
      "Deploy certificates",
    );
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          roleIds: ["10"],
          extraPermissionNames: ["audit:view", "certificate:deploy"],
        }),
      ),
    );
  });

  it("explains that unreadable direct grants are left unchanged", async () => {
    const user = userEvent.setup();
    const { onSave } = renderDialog({
      directGrants: { status: "unavailable" },
    });

    expect(
      screen.getByText(
        "This member's direct permissions couldn't be loaded, so saving leaves them unchanged.",
      ),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ extraPermissionNames: [] }),
      ),
    );
  });
});

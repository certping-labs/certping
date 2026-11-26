// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

import { MembersPanel } from "@/components/settings/organization-access/members-panel";
import { server } from "@/test/msw/server";

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

const mockAuthState = {
  user: {
    id: "admin-1",
    email: "admin@acme.test",
    organizationId: "7",
    organizationName: "Acme",
    roles: ["ORGANIZATION_ADMIN"],
    permissions: [
      "users:view",
      "users:manage",
      "roles:view",
      "permissions:view",
      "permissions:assign",
    ],
    authMethod: "LOCAL" as const,
  },
  isSuperAdmin: false,
  isLoading: false,
};

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => mockAuthState,
}));

jest.mock("@/hooks/use-responsive-view-mode", () => ({
  useResponsiveViewMode: () => ["card", jest.fn()],
}));

const API = process.env.NEXT_PUBLIC_API_URL as string;
const MEMBER_ID = 42;

const ROLES = [
  {
    id: 10,
    name: "MEMBER",
    isSystemRole: true,
    permissions: ["certificate:view", "deployments:view"],
  },
  {
    id: 11,
    name: "OPERATOR",
    isSystemRole: false,
    permissions: ["certificate:view", "certificate:deploy"],
  },
  {
    id: 12,
    name: "ORGANIZATION_ADMIN",
    isSystemRole: true,
    permissions: ["organization:manage", "users:manage"],
  },
];

const PERMISSION_CATALOGUE = [
  { id: 1, name: "certificate:view", description: "View certificates" },
  { id: 2, name: "certificate:deploy", description: "Deploy certificates" },
  { id: 3, name: "deployments:view", description: "View deployments" },
  { id: 4, name: "audit:view", description: "View audit log" },
  { id: 5, name: "users:manage", description: "Manage members" },
];

interface RecordedCall {
  method: string;
  path: string;
  body: unknown;
}

interface Scenario {
  memberRoles: string[];
  directGrants: string[] | "forbidden";
  failPermissionsUpdate?: boolean;
}

const toPermissionDtos = (names: string[]) =>
  names.map((name, index) => ({ id: 100 + index, name }));

function stubScenario({
  memberRoles,
  directGrants,
  failPermissionsUpdate = false,
}: Scenario): RecordedCall[] {
  const calls: RecordedCall[] = [];
  const record = async (request: Request) => {
    calls.push({
      method: request.method,
      path: new URL(request.url).pathname,
      body: await request.json(),
    });
  };

  server.use(
    http.get(`${API}/api/v1/users/organization`, () =>
      HttpResponse.json([
        {
          id: MEMBER_ID,
          email: "jane@acme.test",
          username: "jane",
          displayName: "Jane Doe",
          roles: memberRoles,
          active: true,
          authMethod: "LOCAL",
        },
      ]),
    ),
    http.get(`${API}/api/v1/roles`, () => HttpResponse.json(ROLES)),
    http.get(`${API}/api/v1/permissions`, () =>
      HttpResponse.json(PERMISSION_CATALOGUE),
    ),
    http.get(`${API}/api/v1/users/${MEMBER_ID}/permissions`, () =>
      directGrants === "forbidden"
        ? HttpResponse.json({ message: "Access denied" }, { status: 403 })
        : HttpResponse.json(toPermissionDtos(directGrants)),
    ),
    http.put(
      `${API}/api/v1/users/organization/${MEMBER_ID}`,
      async ({ request }) => {
        await record(request);
        return HttpResponse.json({ id: MEMBER_ID, email: "jane@acme.test" });
      },
    ),
    http.put(`${API}/api/v1/users/${MEMBER_ID}/roles`, async ({ request }) => {
      await record(request);
      return new HttpResponse(null, { status: 204 });
    }),
    http.put(
      `${API}/api/v1/users/${MEMBER_ID}/permissions`,
      async ({ request }) => {
        await record(request);
        return failPermissionsUpdate
          ? HttpResponse.json(
              { message: "Permission is not grantable" },
              { status: 403 },
            )
          : HttpResponse.json([]);
      },
    ),
  );

  return calls;
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MembersPanel />
    </QueryClientProvider>,
  );
}

async function openEditDialog(user: ReturnType<typeof userEvent.setup>) {
  renderPage();
  await user.click(await screen.findByRole("button", { name: "Manage" }));
  await user.click(
    await screen.findByRole("menuitem", { name: "Edit member" }),
  );
  const dialog = await screen.findByRole("dialog", { name: "Edit member" });
  await within(dialog).findByLabelText(/^Email/);
  return dialog;
}

function comboboxFor(dialog: HTMLElement, label: string) {
  const field = within(dialog).getByText(label, { selector: "label" })
    .parentElement as HTMLElement;
  return within(field).getByRole("combobox");
}

async function pickOption(
  user: ReturnType<typeof userEvent.setup>,
  dialog: HTMLElement,
  comboboxLabel: string,
  optionName: string,
) {
  await user.click(comboboxFor(dialog, comboboxLabel));
  await user.click(await screen.findByRole("option", { name: optionName }));
  await user.keyboard("{Escape}");
}

const paths = (calls: RecordedCall[]) =>
  calls.map((call) => `${call.method} ${call.path}`);

describe("Teams page: edit member access", () => {
  beforeAll(() => {
    global.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  it("saves a member with roles only without sending any direct grants", async () => {
    const calls = stubScenario({ memberRoles: ["MEMBER"], directGrants: [] });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    const fromRoles = within(dialog).getByRole("list", {
      name: "Permissions from roles",
    });
    expect(
      within(fromRoles).getByText("View certificates"),
    ).toBeInTheDocument();
    expect(within(fromRoles).getAllByText("From Member")).toHaveLength(2);

    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Member updated"),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
    ]);
  });

  it("sends just the one extra permission the admin added", async () => {
    const calls = stubScenario({ memberRoles: ["MEMBER"], directGrants: [] });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    await user.click(comboboxFor(dialog, "Additional permissions"));
    expect(
      screen.queryByRole("option", { name: "View certificates" }),
    ).not.toBeInTheDocument();
    await user.click(
      await screen.findByRole("option", { name: "View audit log" }),
    );
    await user.keyboard("{Escape}");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Member updated"),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
      `PUT /api/v1/users/${MEMBER_ID}/permissions`,
    ]);
    expect(calls[1].body).toEqual({ permissionNames: ["audit:view"] });
  });

  it("removes a role without leaving its permissions behind as direct grants", async () => {
    const calls = stubScenario({
      memberRoles: ["MEMBER", "OPERATOR"],
      directGrants: [
        "certificate:deploy",
        "certificate:view",
        "deployments:view",
      ],
    });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    expect(comboboxFor(dialog, "Additional permissions")).toHaveTextContent(
      "Add permissions beyond the roles...",
    );

    await user.click(
      within(dialog).getByRole("button", { name: "Remove Operator" }),
    );
    const fromRoles = within(dialog).getByRole("list", {
      name: "Permissions from roles",
    });
    expect(
      within(fromRoles).queryByText("Deploy certificates"),
    ).not.toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Member updated"),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
      `PUT /api/v1/users/${MEMBER_ID}/roles`,
      `PUT /api/v1/users/${MEMBER_ID}/permissions`,
    ]);
    expect(calls[1].body).toEqual({ roleIds: [10] });
    expect(calls[2].body).toEqual({ permissionNames: [] });
  });

  it("keeps an extra permission when a role that covers it is added and removed again", async () => {
    const calls = stubScenario({
      memberRoles: ["MEMBER"],
      directGrants: ["certificate:deploy"],
    });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    await pickOption(user, dialog, "Roles", "Operator");
    await user.click(
      within(dialog).getByRole("button", { name: "Remove Operator" }),
    );
    expect(comboboxFor(dialog, "Additional permissions")).toHaveTextContent(
      "Deploy certificates",
    );
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Member updated"),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
    ]);
  });

  it("promotes a member to org admin without granting organization:manage directly", async () => {
    const calls = stubScenario({ memberRoles: ["MEMBER"], directGrants: [] });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    await pickOption(user, dialog, "Roles", "Organization Admin");
    expect(
      within(
        within(dialog).getByRole("list", { name: "Permissions from roles" }),
      ).getByText("organization:manage"),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Member updated"),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
      `PUT /api/v1/users/${MEMBER_ID}/roles`,
    ]);
    expect(calls[1].body).toEqual({ roleIds: [10, 12] });
  });

  it("names the step that failed and keeps the dialog open", async () => {
    const calls = stubScenario({
      memberRoles: ["MEMBER"],
      directGrants: [],
      failPermissionsUpdate: true,
    });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    await pickOption(user, dialog, "Roles", "Operator");
    await pickOption(user, dialog, "Additional permissions", "View audit log");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "Profile and roles saved. Additional permissions were not updated: Permission is not grantable",
      ),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
      `PUT /api/v1/users/${MEMBER_ID}/roles`,
      `PUT /api/v1/users/${MEMBER_ID}/permissions`,
    ]);
    expect(screen.getByRole("dialog", { name: "Edit member" })).toBeVisible();

    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() => expect(calls).toHaveLength(5));
    expect(paths(calls).slice(3)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
      `PUT /api/v1/users/${MEMBER_ID}/permissions`,
    ]);
  });

  it("leaves direct grants untouched when they cannot be read", async () => {
    const calls = stubScenario({
      memberRoles: ["MEMBER"],
      directGrants: "forbidden",
    });
    const user = userEvent.setup();

    const dialog = await openEditDialog(user);
    expect(
      within(dialog).getByText(/direct permissions couldn't be loaded/),
    ).toBeInTheDocument();
    await pickOption(user, dialog, "Roles", "Operator");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith("Member updated"),
    );
    expect(paths(calls)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
      `PUT /api/v1/users/${MEMBER_ID}/roles`,
    ]);
    expect(calls[1].body).toEqual({ roleIds: [10, 11] });
  });
});

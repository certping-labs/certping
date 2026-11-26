// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

import { MembersPanel } from "@/components/settings/organization-access/members-panel";
import { useFeatureFlagStore } from "@/stores/feature-flag-store";
import { server } from "@/test/msw/server";

// The shared setup stubs every flag as loaded; these tests drive the real
// load state (pending, error, ready).
jest.mock("@/hooks/use-feature-flags", () =>
  jest.requireActual("@/hooks/use-feature-flags"),
);

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
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
        "roles:create",
        "permissions:view",
        "permissions:assign",
      ],
      authMethod: "LOCAL" as const,
    },
    isSuperAdmin: false,
    isLoading: false,
  }),
}));

jest.mock("@/hooks/use-responsive-view-mode", () => ({
  useResponsiveViewMode: () => ["card", jest.fn()],
}));

const API = process.env.NEXT_PUBLIC_API_URL as string;
const MEMBER_ID = 42;
const WAITING = "Checking which features are on. You can save in a moment.";

// Backend-realistic: Discovery is off, so its role (DISCOVERY_SCANNER) and
// permissions (discovery:*) are absent from every response. The backend
// keeps them on save; the client never sees or sends them.
const CATALOGUE = [
  { id: 1, name: "certificate:view", description: "View certificates" },
  { id: 5, name: "deployments:view", description: "View deployments" },
  { id: 6, name: "audit:view", description: "View audit log" },
];

const ROLES = [
  {
    id: 10,
    name: "MEMBER",
    isSystemRole: true,
    permissions: ["certificate:view"],
  },
  {
    id: 11,
    name: "OPERATOR",
    isSystemRole: false,
    permissions: ["certificate:view", "deployments:view"],
  },
];

interface RecordedCall {
  method: string;
  path: string;
  body: unknown;
}

const permissionDtos = (names: string[]) =>
  CATALOGUE.filter((permission) => names.includes(permission.name));

function stubApi({ active = true } = {}): RecordedCall[] {
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
          roles: ["MEMBER"],
          active,
          authMethod: "LOCAL",
        },
      ]),
    ),
    http.get(`${API}/api/v1/roles`, () => HttpResponse.json(ROLES)),
    http.get(`${API}/api/v1/permissions`, () => HttpResponse.json(CATALOGUE)),
    http.get(`${API}/api/v1/roles/10/permissions`, () =>
      HttpResponse.json(permissionDtos(ROLES[0].permissions)),
    ),
    http.get(`${API}/api/v1/users/${MEMBER_ID}/permissions`, () =>
      HttpResponse.json([]),
    ),
    http.put(`${API}/api/v1/roles/10/permissions`, async ({ request }) => {
      await record(request);
      return HttpResponse.json(ROLES[0]);
    }),
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
        return HttpResponse.json([]);
      },
    ),
  );
  return calls;
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MembersPanel />
    </QueryClientProvider>,
  );
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

async function openEditMember(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Manage" }));
  await user.click(
    await screen.findByRole("menuitem", { name: "Edit member" }),
  );
  const dialog = await screen.findByRole("dialog", { name: "Edit member" });
  await within(dialog).findByLabelText(/^Email/);
  return dialog;
}

async function openEditRole(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("tab", { name: "Roles (2)" }));
  await screen.findByText("Operator");
  await user.click(screen.getAllByRole("button", { name: "Edit" })[0]);
  const dialog = await screen.findByRole("dialog", {
    name: "Edit Permissions - MEMBER",
  });
  await waitFor(() =>
    expect(comboboxFor(dialog, "Permissions")).toHaveTextContent(
      "View certificates",
    ),
  );
  return dialog;
}

/** Saves a member edit and returns the role and direct-grant PUT bodies. */
async function saveMemberWithOperatorAndAudit(
  user: ReturnType<typeof userEvent.setup>,
  calls: RecordedCall[],
) {
  const dialog = await openEditMember(user);
  await pickOption(user, dialog, "Roles", "Operator");
  await pickOption(user, dialog, "Additional permissions", "View audit log");
  await user.click(within(dialog).getByRole("button", { name: "Save" }));
  await waitFor(() =>
    expect(toast.success).toHaveBeenCalledWith("Member updated"),
  );
  return {
    roles: calls.find((call) => call.path.endsWith("/roles"))?.body,
    grants: calls.find((call) =>
      call.path.endsWith(`/users/${MEMBER_ID}/permissions`),
    )?.body,
  };
}

describe("Teams page: access saves", () => {
  beforeAll(() => {
    global.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  afterEach(() => {
    useFeatureFlagStore.getState().reset();
  });

  describe("with flags loaded", () => {
    beforeEach(() => {
      useFeatureFlagStore
        .getState()
        .setEffectiveMap({ DISCOVERY: false, CERTIFICATE_DEPLOYMENT: true });
    });

    it("shows exactly the roles and permissions the backend returns", async () => {
      stubApi();
      const user = userEvent.setup();
      renderPage();

      await user.click(await screen.findByRole("tab", { name: "Roles (2)" }));
      expect(await screen.findByText("Operator")).toBeInTheDocument();
      expect(screen.getByText("deployments:view")).toBeInTheDocument();
    });

    it("sends exactly the visible selection when a member is edited", async () => {
      const calls = stubApi();
      const user = userEvent.setup();
      renderPage();

      const { roles, grants } = await saveMemberWithOperatorAndAudit(
        user,
        calls,
      );

      expect(roles).toEqual({ roleIds: [10, 11] });
      expect(grants).toEqual({ permissionNames: ["audit:view"] });
    });

    it("sends exactly the visible selection when a role is edited", async () => {
      const calls = stubApi();
      const user = userEvent.setup();
      renderPage();

      const dialog = await openEditRole(user);
      await pickOption(user, dialog, "Permissions", "View audit log");
      await user.click(within(dialog).getByRole("button", { name: "Save" }));

      await waitFor(() =>
        expect(toast.success).toHaveBeenCalledWith("Role permissions updated"),
      );
      expect(calls).toHaveLength(1);
      const sent = (calls[0].body as { permissionNames: string[] })
        .permissionNames;
      expect([...sent].sort()).toEqual(["audit:view", "certificate:view"]);
    });

    it("re-enables a member without re-sending their roles", async () => {
      const calls = stubApi({ active: false });
      const user = userEvent.setup();
      renderPage();

      await user.click(await screen.findByRole("button", { name: "Manage" }));
      await user.click(
        await screen.findByRole("menuitem", { name: "Enable member" }),
      );

      await waitFor(() =>
        expect(toast.success).toHaveBeenCalledWith("Member enabled"),
      );
      const profile = calls.find((call) =>
        call.path.endsWith(`/organization/${MEMBER_ID}`),
      );
      expect(profile?.body).toMatchObject({ active: true, enabled: true });
      expect(profile?.body).not.toHaveProperty("roles");
      expect(calls.some((call) => call.path.endsWith("/roles"))).toBe(false);
    });
  });

  describe("while the feature flags are still loading", () => {
    it("holds the member save and says why", async () => {
      const calls = stubApi();
      const user = userEvent.setup();
      renderPage();

      const dialog = await openEditMember(user);
      const save = within(dialog).getByRole("button", { name: "Save" });
      expect(save).toBeDisabled();
      expect(save).toHaveAccessibleDescription(WAITING);
      expect(calls).toHaveLength(0);
    });

    it("holds the role save and says why", async () => {
      stubApi();
      const user = userEvent.setup();
      renderPage();

      const dialog = await openEditRole(user);
      const save = within(dialog).getByRole("button", { name: "Save" });
      expect(save).toBeDisabled();
      expect(save).toHaveAccessibleDescription(WAITING);
    });

    it("holds re-enabling a member and says why", async () => {
      const calls = stubApi({ active: false });
      const user = userEvent.setup();
      renderPage();

      await user.click(await screen.findByRole("button", { name: "Manage" }));
      const enable = await screen.findByRole("menuitem", {
        name: /^Enable member/,
      });
      expect(enable).toHaveAttribute("aria-disabled", "true");
      expect(enable).toHaveTextContent(WAITING);
      expect(calls).toHaveLength(0);
    });

    it("lets the save through once the flags load", async () => {
      const calls = stubApi();
      const user = userEvent.setup();
      renderPage();

      const dialog = await openEditMember(user);
      expect(
        within(dialog).getByRole("button", { name: "Save" }),
      ).toBeDisabled();

      useFeatureFlagStore.getState().setEffectiveMap({});
      await waitFor(() =>
        expect(
          within(dialog).getByRole("button", { name: "Save" }),
        ).toBeEnabled(),
      );
      await user.click(within(dialog).getByRole("button", { name: "Save" }));
      await waitFor(() =>
        expect(toast.success).toHaveBeenCalledWith("Member updated"),
      );
      expect(calls.length).toBeGreaterThan(0);
    });
  });

  describe("when the feature flags failed to load", () => {
    beforeEach(() => {
      useFeatureFlagStore.getState().markLoadFailed();
    });

    it("still saves, sending exactly the visible selection", async () => {
      const calls = stubApi();
      const user = userEvent.setup();
      renderPage();

      const { roles, grants } = await saveMemberWithOperatorAndAudit(
        user,
        calls,
      );

      expect(screen.queryByText(WAITING)).not.toBeInTheDocument();
      expect(roles).toEqual({ roleIds: [10, 11] });
      expect(grants).toEqual({ permissionNames: ["audit:view"] });
    });
  });
});

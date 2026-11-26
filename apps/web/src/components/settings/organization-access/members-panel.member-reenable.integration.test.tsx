// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { toast } from "sonner";

import { MembersPanel } from "@/components/settings/organization-access/members-panel";
import { server } from "@/test/msw/server";

jest.mock("sonner", () => ({
  toast: { success: jest.fn(), error: jest.fn() },
}));

let mockPermissions: string[] = [];

jest.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({
    user: {
      id: "admin-1",
      email: "admin@acme.test",
      organizationId: "7",
      organizationName: "Acme",
      roles: ["MEMBER_ADMIN"],
      permissions: mockPermissions,
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

interface RecordedCall {
  method: string;
  path: string;
  body: unknown;
}

/** Stubs a disabled member; `rolesStatus` decides how the roles list answers. */
function stubApi(rolesStatus: number): RecordedCall[] {
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
          roles: ["MEMBER", "DEPLOYMENT_MANAGER"],
          active: false,
          authMethod: "LOCAL",
        },
      ]),
    ),
    http.get(`${API}/api/v1/roles`, () =>
      HttpResponse.json(
        { status: rolesStatus, message: "roles unavailable" },
        { status: rolesStatus },
      ),
    ),
    http.get(`${API}/api/v1/permissions`, () => HttpResponse.json([])),
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
  );
  return calls;
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MembersPanel />
    </QueryClientProvider>,
  );
}

async function enableMember() {
  const user = userEvent.setup();
  renderPage();
  await user.click(await screen.findByRole("button", { name: "Manage" }));
  await user.click(
    await screen.findByRole("menuitem", { name: "Enable member" }),
  );
  await waitFor(() =>
    expect(toast.success).toHaveBeenCalledWith("Member enabled"),
  );
}

describe("Teams page: re-enabling a member leaves roles untouched", () => {
  beforeAll(() => {
    global.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  it.each<[string, string[], number]>([
    [
      "the roles query is disabled (no roles permission)",
      ["users:view", "users:manage"],
      200,
    ],
    [
      "the roles query failed",
      ["users:view", "users:manage", "roles:view"],
      500,
    ],
  ])("sends no roles PUT when %s", async (_label, permissions, rolesStatus) => {
    mockPermissions = permissions;
    const calls = stubApi(rolesStatus);

    await enableMember();

    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      `PUT /api/v1/users/organization/${MEMBER_ID}`,
    ]);
    expect(calls[0].body).toMatchObject({ active: true, enabled: true });
    expect(calls[0].body).not.toHaveProperty("roles");
    expect(toast.error).not.toHaveBeenCalledWith(
      expect.stringContaining("Failed to enable member"),
    );
  });
});

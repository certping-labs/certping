// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";

import {
  PERMISSIONS_QUERY_KEY,
  ROLES_QUERY_KEY,
  USERS_QUERY_KEY,
  useAddUserPermissions,
  useAssignUserRoles,
  useCreateRole,
  useCreateUser,
  useDeleteRole,
  useDeleteUser,
  useDisableUser,
  useGetRole,
  useGetRolePermissions,
  useGetUser,
  useGetUserPermissions,
  useListPermissions,
  useListPermissionsByResource,
  useListRoles,
  useListUsers,
  useRemoveUserPermissions,
  useUpdateRolePermissions,
  useUpdateUser,
  useUpdateUserPermissions,
} from "@/hooks/users";
import * as usersBackend from "@/lib/backend/users";

jest.mock("@/lib/backend/users");

const backend = usersBackend as jest.Mocked<typeof usersBackend>;
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { queryClient, wrapper };
}

beforeEach(() => {
  jest.clearAllMocks();
  // Mutations log failures rather than surfacing them; silence the noise but
  // keep the spy so the tests can assert the handler ran.
  jest.spyOn(console, "error").mockImplementation(() => {});
});

describe("team read hooks", () => {
  it("does not fetch a user until it has an id", async () => {
    const { wrapper } = createWrapper();
    const { result } = renderHook(() => useGetUser(undefined), { wrapper });

    expect(backend.getUserById).not.toHaveBeenCalled();
    expect(result.current.fetchStatus).toBe("idle");
  });

  it("fetches a user once an id is available", async () => {
    backend.getUserById.mockResolvedValue({ id: 7 } as never);
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useGetUser(7), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(backend.getUserById).toHaveBeenCalledWith(7);
  });

  it("respects an explicit disable even when an id is present", () => {
    const { wrapper } = createWrapper();
    renderHook(() => useGetUser(7, { enabled: false }), { wrapper });
    expect(backend.getUserById).not.toHaveBeenCalled();
  });

  it("caches organization-scoped and global user lists separately", async () => {
    // Both lists are "users"; sharing one cache entry would show an admin the
    // wrong organization's members.
    backend.listUsers.mockResolvedValue([] as never);
    const { wrapper } = createWrapper();

    renderHook(() => useListUsers({ organizationScoped: true }), { wrapper });
    renderHook(() => useListUsers({ organizationScoped: false }), { wrapper });

    await waitFor(() => expect(backend.listUsers).toHaveBeenCalledTimes(2));
    expect(backend.listUsers).toHaveBeenCalledWith(true);
    expect(backend.listUsers).toHaveBeenCalledWith(false);
  });

  it("fetches a role by id", async () => {
    backend.getRoleById.mockResolvedValue({ id: 3, name: "Auditor" } as never);
    const { wrapper } = createWrapper();

    renderHook(() => useGetRole(3), { wrapper });

    await waitFor(() => expect(backend.getRoleById).toHaveBeenCalledWith(3));
  });

  it("fetches a role's permissions by id", async () => {
    backend.getRolePermissions.mockResolvedValue([] as never);
    const { wrapper } = createWrapper();

    renderHook(() => useGetRolePermissions(3), { wrapper });

    await waitFor(() =>
      expect(backend.getRolePermissions).toHaveBeenCalledWith(3),
    );
  });

  it("fetches a user's permissions by id", async () => {
    backend.getUserPermissions.mockResolvedValue([] as never);
    const { wrapper } = createWrapper();

    renderHook(() => useGetUserPermissions(3), { wrapper });

    await waitFor(() =>
      expect(backend.getUserPermissions).toHaveBeenCalledWith(3),
    );
  });

  it("lists roles and permissions", async () => {
    backend.listRoles.mockResolvedValue([] as never);
    backend.listPermissions.mockResolvedValue([] as never);
    backend.listPermissionsByResource.mockResolvedValue([] as never);
    const { wrapper } = createWrapper();

    renderHook(() => useListRoles(), { wrapper });
    renderHook(() => useListPermissions(), { wrapper });
    renderHook(() => useListPermissionsByResource("certificate"), { wrapper });

    await waitFor(() => expect(backend.listRoles).toHaveBeenCalled());
    expect(backend.listPermissions).toHaveBeenCalled();
    expect(backend.listPermissionsByResource).toHaveBeenCalledWith(
      "certificate",
    );
  });
});

describe("team mutations", () => {
  /** Every team mutation must refresh the member list it just changed. */
  async function expectInvalidatesTeamQueries(
    run: (queryClient: QueryClient) => Promise<void>,
  ) {
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");
    await run(queryClient);
    const invalidatedKeys = invalidateSpy.mock.calls
      .map((call) => JSON.stringify(call[0]?.queryKey ?? []))
      .join(" ");
    expect(invalidatedKeys).toContain(USERS_QUERY_KEY);
    return { wrapper, invalidatedKeys };
  }

  it("creates a member", async () => {
    backend.createUser.mockResolvedValue({ id: 1 } as never);
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useCreateUser(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ email: "a@b.com" } as never);
    });

    expect(backend.createUser).toHaveBeenCalledWith({ email: "a@b.com" });
  });

  it("refreshes the member list after creating a member", async () => {
    backend.createUser.mockResolvedValue({ id: 1 } as never);
    await expectInvalidatesTeamQueries(async (queryClient) => {
      const wrapper = ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>
          {children}
        </QueryClientProvider>
      );
      const { result } = renderHook(() => useCreateUser(), { wrapper });
      await act(async () => {
        await result.current.mutateAsync({ email: "a@b.com" } as never);
      });
    });
  });

  it("passes the organization scope through on update, delete and disable", async () => {
    backend.updateUser.mockResolvedValue({} as never);
    backend.deleteUser.mockResolvedValue({} as never);
    backend.disableUser.mockResolvedValue({} as never);
    const { wrapper } = createWrapper();

    const update = renderHook(() => useUpdateUser(), { wrapper });
    const remove = renderHook(() => useDeleteUser(), { wrapper });
    const disable = renderHook(() => useDisableUser(), { wrapper });

    await act(async () => {
      await update.result.current.mutateAsync({
        id: 1,
        payload: { firstName: "A" } as never,
        organizationScoped: true,
      });
      await remove.result.current.mutateAsync({
        id: 2,
        organizationScoped: true,
      });
      await disable.result.current.mutateAsync({
        id: 3,
        organizationScoped: false,
      } as never);
    });

    // Dropping the scope would route an org-admin's edit at the global
    // endpoint, which they are not authorized for.
    expect(backend.updateUser).toHaveBeenCalledWith(
      1,
      { firstName: "A" },
      true,
    );
    expect(backend.deleteUser).toHaveBeenCalledWith(2, true);
    expect(backend.disableUser).toHaveBeenCalled();
  });

  it("reports a failed mutation instead of resolving quietly", async () => {
    backend.createUser.mockRejectedValue(new Error("409"));
    const { wrapper } = createWrapper();

    const { result } = renderHook(() => useCreateUser(), { wrapper });
    await act(async () => {
      await result.current
        .mutateAsync({ email: "a@b.com" } as never)
        .catch(() => undefined);
    });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(console.error).toHaveBeenCalled();
  });

  it("applies permission changes through their own endpoints", async () => {
    backend.updateUserPermissions.mockResolvedValue({} as never);
    backend.addUserPermissions.mockResolvedValue({} as never);
    backend.removeUserPermissions.mockResolvedValue({} as never);
    backend.assignUserRoles.mockResolvedValue({} as never);
    const { wrapper } = createWrapper();

    const replace = renderHook(() => useUpdateUserPermissions(), { wrapper });
    const add = renderHook(() => useAddUserPermissions(), { wrapper });
    const remove = renderHook(() => useRemoveUserPermissions(), { wrapper });
    const roles = renderHook(() => useAssignUserRoles(), { wrapper });

    await act(async () => {
      await replace.result.current.mutateAsync({
        id: 1,
        permissions: ["a"],
      } as never);
      await add.result.current.mutateAsync({
        id: 1,
        permissions: ["b"],
      } as never);
      await remove.result.current.mutateAsync({
        id: 1,
        permissions: ["c"],
      } as never);
      await roles.result.current.mutateAsync({
        id: 1,
        roles: ["ADMIN"],
      } as never);
    });

    expect(backend.updateUserPermissions).toHaveBeenCalled();
    expect(backend.addUserPermissions).toHaveBeenCalled();
    expect(backend.removeUserPermissions).toHaveBeenCalled();
    expect(backend.assignUserRoles).toHaveBeenCalled();
  });

  it("manages roles and refreshes the role list", async () => {
    backend.createRole.mockResolvedValue({} as never);
    backend.updateRolePermissions.mockResolvedValue({} as never);
    backend.deleteRole.mockResolvedValue({} as never);
    const { queryClient, wrapper } = createWrapper();
    const invalidateSpy = jest.spyOn(queryClient, "invalidateQueries");

    const create = renderHook(() => useCreateRole(), { wrapper });
    const update = renderHook(() => useUpdateRolePermissions(), { wrapper });
    const remove = renderHook(() => useDeleteRole(), { wrapper });

    await act(async () => {
      await create.result.current.mutateAsync({ name: "Auditor" } as never);
      await update.result.current.mutateAsync({
        id: 1,
        permissions: ["audit:view"],
      } as never);
      await remove.result.current.mutateAsync(1 as never);
    });

    expect(backend.createRole).toHaveBeenCalled();
    expect(backend.updateRolePermissions).toHaveBeenCalled();
    expect(backend.deleteRole).toHaveBeenCalledWith(1);
    expect(invalidateSpy).toHaveBeenCalled();
  });
});

describe("query keys", () => {
  it("are distinct per resource so one invalidation does not clear the others", () => {
    expect(
      new Set([USERS_QUERY_KEY, ROLES_QUERY_KEY, PERMISSIONS_QUERY_KEY]).size,
    ).toBe(3);
  });
});

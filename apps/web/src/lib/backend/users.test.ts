// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    },
  };
});

import { apiClient, apiRoutes } from "@/lib/api";
import {
  addUserPermissions,
  assignUserRoles,
  createRole,
  createUser,
  deleteRole,
  deleteUser,
  disableUser,
  getRoleById,
  getRolePermissions,
  getUserById,
  getUserPermissions,
  listPermissions,
  listPermissionsByResource,
  listRoles,
  listUsers,
  removeUserPermissions,
  updateRolePermissions,
  updateUser,
  updateUserPermissions,
} from "@/lib/backend/users";

const mockedApiClient = apiClient as unknown as {
  get: jest.Mock;
  post: jest.Mock;
  put: jest.Mock;
  delete: jest.Mock;
};

describe("users adapter", () => {
  beforeEach(() => {
    mockedApiClient.get.mockReset();
    mockedApiClient.post.mockReset();
    mockedApiClient.put.mockReset();
    mockedApiClient.delete.mockReset();
  });

  it("returns a user by id using the backend DTO", async () => {
    mockedApiClient.get.mockResolvedValue({
      data: {
        id: 10,
        email: "alice@example.com",
        username: "alice",
        displayName: "Alice",
        organizationId: 1,
        organizationName: "Tenant One",
        authMethod: "SSO",
        mustChangePassword: true,
        roles: ["ADMIN"],
        permissions: ["users:view"],
        active: false,
      },
    });

    const user = await getUserById(10);

    expect(mockedApiClient.get).toHaveBeenCalledWith(
      apiRoutes.query.users.detail(10),
    );
    expect(user).toEqual(
      expect.objectContaining({
        id: 10,
        email: "alice@example.com",
        username: "alice",
        organizationId: 1,
        organizationName: "Tenant One",
        authMethod: "SSO",
        mustChangePassword: true,
        roles: ["ADMIN"],
        permissions: ["users:view"],
        active: false,
      }),
    );
  });

  it("lists users for global and organization scoped routes", async () => {
    mockedApiClient.get
      .mockResolvedValueOnce({
        data: [{ id: 1, email: "global@example.com", authMethod: "LOCAL" }],
      })
      .mockResolvedValueOnce({
        data: [{ id: 2, email: "org@example.com", authMethod: "SSO" }],
      })
      .mockResolvedValueOnce({ data: [] });

    await expect(listUsers(false)).resolves.toEqual([
      expect.objectContaining({
        id: 1,
        email: "global@example.com",
        authMethod: "LOCAL",
      }),
    ]);
    await expect(listUsers(true)).resolves.toEqual([
      expect.objectContaining({
        id: 2,
        email: "org@example.com",
        authMethod: "SSO",
      }),
    ]);
    await expect(listUsers()).resolves.toEqual([]);

    expect(mockedApiClient.get).toHaveBeenNthCalledWith(
      1,
      apiRoutes.query.users.list,
    );
    expect(mockedApiClient.get).toHaveBeenNthCalledWith(
      2,
      apiRoutes.query.users.organizationList,
    );
  });

  it("creates and updates users with correct route selection", async () => {
    const createPayload = {
      email: "created@example.com",
      password: "Secret#123",
      username: "created",
      displayName: "Created User",
      roleIds: [1],
    };
    mockedApiClient.post.mockResolvedValueOnce({
      data: { id: 3, email: "created@example.com", roles: ["ADMIN"] },
    });
    mockedApiClient.put
      .mockResolvedValueOnce({
        data: { id: 4, email: "global-updated@example.com" },
      })
      .mockResolvedValueOnce({
        data: { id: 5, email: "org-updated@example.com" },
      });

    const created = await createUser(createPayload);
    const globalUpdated = await updateUser(
      4,
      { email: "global-updated@example.com" },
      false,
    );
    const orgUpdated = await updateUser(
      5,
      { email: "org-updated@example.com" },
      true,
    );

    expect(mockedApiClient.post).toHaveBeenCalledWith(
      apiRoutes.mutation.users.create,
      createPayload,
    );
    expect(mockedApiClient.put).toHaveBeenNthCalledWith(
      1,
      apiRoutes.mutation.users.update(4),
      { email: "global-updated@example.com" },
    );
    expect(mockedApiClient.put).toHaveBeenNthCalledWith(
      2,
      apiRoutes.mutation.users.organizationUpdate(5),
      { email: "org-updated@example.com" },
    );
    expect(created.id).toBe(3);
    expect(globalUpdated.email).toBe("global-updated@example.com");
    expect(orgUpdated.email).toBe("org-updated@example.com");
  });

  it("deletes and disables users for both scopes", async () => {
    mockedApiClient.delete.mockResolvedValue({});
    mockedApiClient.post.mockResolvedValue({});

    await deleteUser(11, false);
    await deleteUser(12, true);
    await disableUser(13, false);
    await disableUser(14, true);

    expect(mockedApiClient.delete).toHaveBeenNthCalledWith(
      1,
      apiRoutes.mutation.users.delete(11),
    );
    expect(mockedApiClient.delete).toHaveBeenNthCalledWith(
      2,
      apiRoutes.mutation.users.organizationDelete(12),
    );
    expect(mockedApiClient.post).toHaveBeenNthCalledWith(
      1,
      apiRoutes.mutation.users.disable(13),
    );
    expect(mockedApiClient.post).toHaveBeenNthCalledWith(
      2,
      apiRoutes.mutation.users.organizationDisable(14),
    );
  });

  it("handles user permission CRUD and role assignment", async () => {
    mockedApiClient.get.mockResolvedValueOnce({
      data: [
        {
          id: 1,
          name: "users:view",
          resource: "users",
          action: "view",
          description: "View users",
        },
      ],
    });
    mockedApiClient.put
      .mockResolvedValueOnce({
        data: [
          { id: 2, name: "users:edit", resource: "users", action: "edit" },
        ],
      })
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({
        data: { id: 77, name: "Role 77", permissions: ["users:view"] },
      });
    mockedApiClient.post
      .mockResolvedValueOnce({
        data: [
          { id: 3, name: "users:create", resource: "users", action: "create" },
        ],
      })
      .mockResolvedValueOnce({});
    mockedApiClient.delete.mockResolvedValueOnce({
      data: [
        { id: 4, name: "users:delete", resource: "users", action: "delete" },
      ],
    });

    await expect(getUserPermissions(40)).resolves.toEqual([
      expect.objectContaining({ id: 1, name: "users:view", resource: "users" }),
    ]);
    await expect(updateUserPermissions(40, ["users:edit"])).resolves.toEqual([
      expect.objectContaining({ id: 2, name: "users:edit" }),
    ]);
    await expect(addUserPermissions(40, ["users:create"])).resolves.toEqual([
      expect.objectContaining({ id: 3, name: "users:create" }),
    ]);
    await expect(removeUserPermissions(40, ["users:delete"])).resolves.toEqual([
      expect.objectContaining({ id: 4, name: "users:delete" }),
    ]);
    await expect(updateUserPermissions(40, [])).resolves.toEqual([]);
    await assignUserRoles(40, [7, 8]);

    expect(mockedApiClient.put).toHaveBeenCalledWith(
      apiRoutes.mutation.users.assignRoles(40),
      { roleIds: [7, 8] },
    );
    expect(mockedApiClient.delete).toHaveBeenCalledWith(
      apiRoutes.mutation.users.updatePermissions(40),
      { permissionNames: ["users:delete"] },
    );
  });

  it("covers typed role and permission endpoints", async () => {
    mockedApiClient.get
      .mockResolvedValueOnce({
        data: [
          {
            id: 1,
            name: "Admin",
            isSystemRole: true,
            permissions: ["users:*"],
          },
        ],
      })
      .mockResolvedValueOnce({
        data: { id: 2, name: "Reader", organizationId: 2 },
      })
      .mockResolvedValueOnce({
        data: [
          { id: 1, name: "users:view", resource: "users", action: "view" },
        ],
      })
      .mockResolvedValueOnce({
        data: [
          { id: 10, name: "certs:view", resource: "certs", action: "view" },
        ],
      })
      .mockResolvedValueOnce({ data: [] });
    mockedApiClient.post.mockResolvedValueOnce({
      data: { id: 3, name: "Writer", description: "Can write" },
    });
    mockedApiClient.put.mockResolvedValueOnce({
      data: { id: 2, name: "Reader", permissions: ["users:view"] },
    });
    mockedApiClient.delete.mockResolvedValue({});

    const roles = await listRoles();
    const createdRole = await createRole({
      name: "Writer",
      description: "Can write",
      permissionNames: ["users:edit"],
      organizationId: 3,
    });
    const roleById = await getRoleById(2);
    const rolePermissions = await getRolePermissions(2);
    const updatedRole = await updateRolePermissions(2, ["users:view"]);
    const allPermissions = await listPermissions();
    const certPermissions = await listPermissionsByResource("certs");

    await deleteRole(3);

    expect(roles[0]).toEqual(
      expect.objectContaining({ id: 1, name: "Admin", isSystemRole: true }),
    );
    expect(createdRole).toEqual(
      expect.objectContaining({
        id: 3,
        name: "Writer",
        description: "Can write",
      }),
    );
    expect(roleById.organizationId).toBe(2);
    expect(rolePermissions[0].name).toBe("users:view");
    expect(updatedRole.permissions).toEqual(["users:view"]);
    expect(allPermissions[0].name).toBe("certs:view");
    expect(certPermissions).toEqual([]);

    expect(mockedApiClient.delete).toHaveBeenCalledWith(
      apiRoutes.mutation.roles.delete(3),
    );
  });
});

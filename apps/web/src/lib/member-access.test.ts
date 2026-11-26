// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  describeMemberSaveFailure,
  getExtraPermissionNames,
  getRoleProvidedPermissionNames,
  getRoleProvidedPermissions,
  planMemberAccessChanges,
  saveMemberEdit,
  type MemberAccessChanges,
  type MemberSaveActions,
} from "@/lib/member-access";

const MEMBER_ROLE_ID = "10";
const OPERATOR_ROLE_ID = "11";
const ORG_ADMIN_ROLE_ID = "12";

const rolePermissionsById = new Map<string, string[]>([
  [MEMBER_ROLE_ID, ["certificate:view", "domains:view"]],
  [OPERATOR_ROLE_ID, ["certificate:view", "certificate:deploy"]],
  [ORG_ADMIN_ROLE_ID, ["organization:manage", "users:manage"]],
]);

describe("getRoleProvidedPermissions", () => {
  it("lists each permission once with every role that grants it, sorted by name", () => {
    expect(
      getRoleProvidedPermissions(
        [MEMBER_ROLE_ID, OPERATOR_ROLE_ID],
        rolePermissionsById,
      ),
    ).toEqual([
      { name: "certificate:deploy", roleIds: [OPERATOR_ROLE_ID] },
      { name: "certificate:view", roleIds: [MEMBER_ROLE_ID, OPERATOR_ROLE_ID] },
      { name: "domains:view", roleIds: [MEMBER_ROLE_ID] },
    ]);
  });

  it("ignores duplicate and unknown role ids", () => {
    expect(
      getRoleProvidedPermissions(
        [MEMBER_ROLE_ID, MEMBER_ROLE_ID, "999"],
        rolePermissionsById,
      ),
    ).toEqual([
      { name: "certificate:view", roleIds: [MEMBER_ROLE_ID] },
      { name: "domains:view", roleIds: [MEMBER_ROLE_ID] },
    ]);
  });

  it("returns nothing when no roles are selected", () => {
    expect(getRoleProvidedPermissions([], rolePermissionsById)).toEqual([]);
  });
});

describe("getRoleProvidedPermissionNames", () => {
  it("returns the union of the roles' permissions", () => {
    expect(
      getRoleProvidedPermissionNames(
        [MEMBER_ROLE_ID, ORG_ADMIN_ROLE_ID],
        rolePermissionsById,
      ),
    ).toEqual(
      new Set([
        "certificate:view",
        "domains:view",
        "organization:manage",
        "users:manage",
      ]),
    );
  });
});

describe("getExtraPermissionNames", () => {
  it("drops permissions the roles already provide, dedupes and sorts the rest", () => {
    expect(
      getExtraPermissionNames(
        ["users:view", "certificate:view", "audit:view", "users:view"],
        [MEMBER_ROLE_ID],
        rolePermissionsById,
      ),
    ).toEqual(["audit:view", "users:view"]);
  });

  it("keeps every permission when no roles are selected", () => {
    expect(
      getExtraPermissionNames(["domains:view"], [], rolePermissionsById),
    ).toEqual(["domains:view"]);
  });
});

describe("planMemberAccessChanges", () => {
  it("sends nothing when the roles and extra permissions are unchanged", () => {
    expect(
      planMemberAccessChanges(
        { roleIds: [MEMBER_ROLE_ID], directPermissionNames: [] },
        { roleIds: [MEMBER_ROLE_ID], extraPermissionNames: [] },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: null, directPermissionNames: null });
  });

  it("treats a reordered role selection as unchanged", () => {
    expect(
      planMemberAccessChanges(
        {
          roleIds: [MEMBER_ROLE_ID, OPERATOR_ROLE_ID],
          directPermissionNames: ["audit:view"],
        },
        {
          roleIds: [OPERATOR_ROLE_ID, MEMBER_ROLE_ID],
          extraPermissionNames: ["audit:view"],
        },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: null, directPermissionNames: null });
  });

  it("sends only the one extra permission that was added", () => {
    expect(
      planMemberAccessChanges(
        { roleIds: [MEMBER_ROLE_ID], directPermissionNames: [] },
        { roleIds: [MEMBER_ROLE_ID], extraPermissionNames: ["audit:view"] },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: null, directPermissionNames: ["audit:view"] });
  });

  it("never stores a role's permissions as direct grants when a role is removed", () => {
    expect(
      planMemberAccessChanges(
        {
          roleIds: [MEMBER_ROLE_ID, OPERATOR_ROLE_ID],
          directPermissionNames: [],
        },
        { roleIds: [MEMBER_ROLE_ID], extraPermissionNames: [] },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: [10], directPermissionNames: null });
  });

  it("promotes to org admin without sending organization:manage as a direct grant", () => {
    expect(
      planMemberAccessChanges(
        { roleIds: [MEMBER_ROLE_ID], directPermissionNames: [] },
        {
          roleIds: [MEMBER_ROLE_ID, ORG_ADMIN_ROLE_ID],
          extraPermissionNames: ["organization:manage"],
        },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: [10, 12], directPermissionNames: null });
  });

  it("clears direct grants that only duplicate the selected roles", () => {
    expect(
      planMemberAccessChanges(
        {
          roleIds: [MEMBER_ROLE_ID],
          directPermissionNames: ["certificate:view", "domains:view"],
        },
        { roleIds: [MEMBER_ROLE_ID], extraPermissionNames: [] },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: null, directPermissionNames: [] });
  });

  it("leaves direct grants alone when they could not be read", () => {
    expect(
      planMemberAccessChanges(
        { roleIds: [MEMBER_ROLE_ID], directPermissionNames: null },
        { roleIds: [OPERATOR_ROLE_ID], extraPermissionNames: ["audit:view"] },
        rolePermissionsById,
      ),
    ).toEqual({ roleIds: [11], directPermissionNames: null });
  });

  it("drops role ids that are not positive integers", () => {
    expect(
      planMemberAccessChanges(
        { roleIds: [], directPermissionNames: null },
        {
          roleIds: [MEMBER_ROLE_ID, "abc", "0", "1.5"],
          extraPermissionNames: [],
        },
        rolePermissionsById,
      ).roleIds,
    ).toEqual([10]);
  });
});

describe("saveMemberEdit", () => {
  const createActions = (
    failingStep?: "profile" | "roles" | "directGrants",
  ) => {
    const calls: string[] = [];
    const failure = new Error("server said no");
    const actions: MemberSaveActions = {
      updateProfile: jest.fn(async () => {
        calls.push("profile");
        if (failingStep === "profile") throw failure;
      }),
      assignRoles: jest.fn(async (roleIds: number[]) => {
        calls.push(`roles:${roleIds.join(",")}`);
        if (failingStep === "roles") throw failure;
      }),
      setDirectGrants: jest.fn(async (permissionNames: string[]) => {
        calls.push(`directGrants:${permissionNames.join(",")}`);
        if (failingStep === "directGrants") throw failure;
      }),
    };
    return { actions, calls, failure };
  };

  const allChanges: MemberAccessChanges = {
    roleIds: [10, 12],
    directPermissionNames: ["audit:view"],
  };

  it("saves the profile, then roles, then direct grants", async () => {
    const { actions, calls } = createActions();

    await expect(saveMemberEdit(allChanges, actions)).resolves.toEqual({
      ok: true,
      savedSteps: ["profile", "roles", "directGrants"],
    });
    expect(calls).toEqual([
      "profile",
      "roles:10,12",
      "directGrants:audit:view",
    ]);
  });

  it("only saves the profile when access is unchanged", async () => {
    const { actions, calls } = createActions();

    await expect(
      saveMemberEdit({ roleIds: null, directPermissionNames: null }, actions),
    ).resolves.toEqual({ ok: true, savedSteps: ["profile"] });
    expect(calls).toEqual(["profile"]);
  });

  it("sends an empty direct grant set when grants are being cleared", async () => {
    const { actions, calls } = createActions();

    await saveMemberEdit({ roleIds: null, directPermissionNames: [] }, actions);

    expect(actions.setDirectGrants).toHaveBeenCalledWith([]);
    expect(calls).toEqual(["profile", "directGrants:"]);
  });

  it.each([
    ["profile", [], ["profile"]],
    ["roles", ["profile"], ["profile", "roles:10,12"]],
    [
      "directGrants",
      ["profile", "roles"],
      ["profile", "roles:10,12", "directGrants:audit:view"],
    ],
  ] as const)(
    "stops at the first failure when the %s step fails",
    async (failingStep, savedSteps, expectedCalls) => {
      const { actions, calls, failure } = createActions(failingStep);

      await expect(saveMemberEdit(allChanges, actions)).resolves.toEqual({
        ok: false,
        failedStep: failingStep,
        savedSteps,
        error: failure,
      });
      expect(calls).toEqual(expectedCalls);
    },
  );
});

describe("describeMemberSaveFailure", () => {
  const error = new Error("boom");

  it("says nothing was saved when the profile update fails", () => {
    expect(
      describeMemberSaveFailure(
        { ok: false, failedStep: "profile", savedSteps: [], error },
        "Email already in use",
      ),
    ).toBe("Failed to update member: Email already in use");
  });

  it("says the profile was saved when the roles update fails", () => {
    expect(
      describeMemberSaveFailure(
        { ok: false, failedStep: "roles", savedSteps: ["profile"], error },
        "Forbidden",
      ),
    ).toBe("Profile saved. Roles were not updated: Forbidden");
  });

  it("says profile and roles were saved when the direct grants fail", () => {
    expect(
      describeMemberSaveFailure(
        {
          ok: false,
          failedStep: "directGrants",
          savedSteps: ["profile", "roles"],
          error,
        },
        "",
      ),
    ).toBe("Profile and roles saved. Additional permissions were not updated");
  });

  it("says only the profile was saved when roles were unchanged", () => {
    expect(
      describeMemberSaveFailure(
        {
          ok: false,
          failedStep: "directGrants",
          savedSteps: ["profile"],
          error,
        },
        "Forbidden",
      ),
    ).toBe("Profile saved. Additional permissions were not updated: Forbidden");
  });
});

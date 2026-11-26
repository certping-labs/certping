// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { apiRoutes } from "@/lib/api";
import {
  getCaConnector,
  listCaConnectors,
} from "@/lib/backend/machine-identity/ca-connectors";
import {
  getCertificate,
  getCertificateHistory,
  listCertificates,
  listDeviceCertificates,
  requestCertificateDeviceSync,
  resolveCertificateListParams,
  revokeCertificate,
} from "@/lib/backend/machine-identity/certificates";
import {
  archiveDevice,
  decommissionDevice,
  getDevice,
  listDeviceEvents,
  listDevices,
  resolveDeviceListParams,
  restoreDevice,
} from "@/lib/backend/machine-identity/devices";
import {
  archiveCertificateProfile,
  createCertificateProfile,
  listCertificateProfiles,
  resolveProfileListParams,
  syncSourceProfiles,
  updateCertificateProfile,
} from "@/lib/backend/machine-identity/profiles";
import {
  listDeviceSourceEvents,
  listDeviceSources,
  resolveDeviceSourceEventParams,
  stopDeviceSourceSync,
  triggerDeviceSourceSync,
} from "@/lib/backend/machine-identity/sources";
import { getIotSummary } from "@/lib/backend/machine-identity/summary";
import { MACHINE_IDENTITY_CONFIG } from "@/lib/machine-identity/config";
import type { CreateCertificateProfileRequest } from "@/types/machine-identity-backend";

const getMock = jest.fn();
const postMock = jest.fn();
const putMock = jest.fn();
const deleteMock = jest.fn();

jest.mock("@/lib/api", () => {
  const actual = jest.requireActual("@/lib/api");
  return {
    ...actual,
    apiClient: {
      get: (...args: unknown[]) => getMock(...args),
      post: (...args: unknown[]) => postMock(...args),
      put: (...args: unknown[]) => putMock(...args),
      delete: (...args: unknown[]) => deleteMock(...args),
    },
  };
});

/** The params object the adapter actually put on the wire. */
function sentParams(call: unknown[]): Record<string, unknown> {
  return (call[1] as { params: Record<string, unknown> }).params;
}

beforeEach(() => {
  getMock.mockReset().mockResolvedValue({ data: { content: [] } });
  postMock.mockReset().mockResolvedValue({ data: {} });
  putMock.mockReset().mockResolvedValue({ data: {} });
  deleteMock.mockReset().mockResolvedValue({ data: undefined });
});

describe("device list params", () => {
  it("renames the UI's `search` to the wire's `q`", () => {
    expect(resolveDeviceListParams({ search: "laptop" })).toMatchObject({
      q: "laptop",
    });
    expect("search" in resolveDeviceListParams({ search: "laptop" })).toBe(
      false,
    );
  });

  it("sorts by last-seen unless the caller says otherwise", () => {
    expect(resolveDeviceListParams({}).sort).toBe("lastSeenInSourceAt");
    expect(resolveDeviceListParams({ sort: "deviceName" }).sort).toBe(
      "deviceName",
    );
  });

  it("passes every supported filter through untouched", () => {
    expect(
      resolveDeviceListParams({
        source: "src_1",
        status: "ORPHANED",
        complianceState: "NON_COMPLIANT",
        os: "Windows",
      }),
    ).toMatchObject({
      source: "src_1",
      status: "ORPHANED",
      complianceState: "NON_COMPLIANT",
      os: "Windows",
    });
  });

  it("sends the resolved params, not the raw ones", async () => {
    // A pasted serial number arrives with whitespace; the backend's LIKE
    // search would return nothing for it.
    await listDevices({ search: "  laptop  ", size: 10_000 });

    const params = sentParams(getMock.mock.calls[0]);
    expect(getMock).toHaveBeenCalledWith(
      apiRoutes.query.iotDevices.devices,
      expect.anything(),
    );
    expect(params.q).toBe("laptop");
    expect(params.size).toBe(MACHINE_IDENTITY_CONFIG.list.maxPageSize);
  });

  it("escapes an xref into the path rather than concatenating it", async () => {
    await getDevice("dev/../admin");
    expect(getMock.mock.calls[0][0]).toBe(
      "/api/v1/iot/devices/dev%2F..%2Fadmin",
    );
  });

  it("posts archive and restore without a body", async () => {
    postMock.mockResolvedValue({ data: undefined });

    await archiveDevice("dev_1");
    await restoreDevice("dev_1");

    expect(postMock).toHaveBeenNthCalledWith(
      1,
      "/api/v1/iot/devices/dev_1/archive",
    );
    expect(postMock).toHaveBeenNthCalledWith(
      2,
      "/api/v1/iot/devices/dev_1/restore",
    );
  });

  it("posts decommission without a body", async () => {
    postMock.mockResolvedValue({ data: { deviceXref: "dev_1" } });
    await decommissionDevice("dev_1");
    expect(postMock).toHaveBeenCalledWith(
      apiRoutes.mutation.iotDevices.deviceDecommission("dev_1"),
    );
  });

  it("pages device events", async () => {
    await listDeviceEvents("dev_1", { page: 2, size: 10 });
    expect(sentParams(getMock.mock.calls[0])).toMatchObject({
      page: 2,
      size: 10,
    });
  });
});

describe("certificate list params", () => {
  it("defaults to soonest-expiry-first", () => {
    const resolved = resolveCertificateListParams({});
    expect(resolved.sort).toBe("validTo");
    expect(resolved.direction).toBe("asc");
  });

  it("folds sort and direction into Spring's single `sort` param", async () => {
    // These endpoints silently drop a separate `direction`, so sending one
    // would quietly reverse the operator's chosen order.
    await listCertificates({ sort: "validTo", direction: "desc" });

    const params = sentParams(getMock.mock.calls[0]);
    expect(params.sort).toBe("validTo,desc");
    expect("direction" in params).toBe(false);
  });

  it("carries every inventory filter", async () => {
    await listCertificates({
      deviceXref: "dev_1",
      profileXref: "prof_1",
      sourceXref: "src_1",
      caProvider: "EJBCA",
      status: "EXPIRING",
      renewalState: "NUDGING",
      expiringWithinDays: 14,
      search: "cn",
    });

    expect(sentParams(getMock.mock.calls[0])).toMatchObject({
      deviceXref: "dev_1",
      profileXref: "prof_1",
      sourceXref: "src_1",
      caProvider: "EJBCA",
      status: "EXPIRING",
      renewalState: "NUDGING",
      expiringWithinDays: 14,
      q: "cn",
    });
  });

  it("gives a device's certificates the same order as the main list", async () => {
    // This endpoint has no server-side default sort; without one it returns
    // Postgres's arbitrary row order.
    await listDeviceCertificates("dev_1");
    expect(sentParams(getMock.mock.calls[0]).sort).toBe("validTo,asc");
  });

  it("fetches a certificate and its history by xref", async () => {
    getMock.mockResolvedValue({ data: {} });
    await getCertificate("crt_1");
    await getCertificateHistory("crt_1", { page: 1 });

    expect(getMock.mock.calls[0][0]).toBe(
      apiRoutes.query.iotDevices.certificate("crt_1"),
    );
    expect(getMock.mock.calls[1][0]).toBe(
      apiRoutes.query.iotDevices.certificateHistory("crt_1"),
    );
    expect(sentParams(getMock.mock.calls[1]).page).toBe(1);
  });

  it("requests one or many device check-ins in the body", async () => {
    await requestCertificateDeviceSync({
      deviceXrefs: ["dev_1", "dev_2"],
    });

    expect(postMock).toHaveBeenCalledWith(
      apiRoutes.mutation.iotDevices.certificateNudge,
      { deviceXrefs: ["dev_1", "dev_2"] },
    );
  });

  it("requests every eligible device without mixing selection modes", async () => {
    await requestCertificateDeviceSync({ all: true });

    expect(postMock).toHaveBeenCalledWith(
      apiRoutes.mutation.iotDevices.certificateNudge,
      undefined,
      { params: { all: true } },
    );
  });
});

describe("certificate revocation", () => {
  it("sends the idempotency key as a header, not in the body", async () => {
    // The backend reads `Idempotency-Key` off the request; a key in the body
    // would be ignored and every retry would open a new operation.
    await revokeCertificate(
      "crt_1",
      { reason: "KEY_COMPROMISE", operatorNote: "laptop stolen" },
      "key-1",
    );

    const [url, body, config] = postMock.mock.calls[0] as [
      string,
      unknown,
      { headers: Record<string, string> },
    ];
    expect(url).toBe(apiRoutes.mutation.iotDevices.certificateRevoke("crt_1"));
    expect(body).toEqual({
      reason: "KEY_COMPROMISE",
      operatorNote: "laptop stolen",
    });
    expect(config.headers["Idempotency-Key"]).toBe("key-1");
  });

  it("escapes the xref into the revoke path", async () => {
    await revokeCertificate("crt/1", { reason: "SUPERSEDED" }, "key-2");
    expect(postMock.mock.calls[0][0]).toContain("crt%2F1");
  });
});

describe("profile params", () => {
  it("caps the page size at the server's tighter profile limit", () => {
    // The module default allows 200; this endpoint refuses anything over 100.
    expect(resolveProfileListParams({ size: 500 }).size).toBe(100);
  });

  it("sorts by most recently updated by default", () => {
    expect(resolveProfileListParams({}).sort).toBe("updatedAt");
  });

  it("keeps `search` as `search` here, unlike the device and certificate lists", () => {
    expect(resolveProfileListParams({ search: "scep" })).toMatchObject({
      search: "scep",
    });
  });

  it("posts and puts profiles at the right routes", async () => {
    const input = {
      name: "p",
      sourceXref: "src_1",
      lifecycleStatus: "DRAFT",
      targetPlatform: "WINDOWS",
      profileKind: "CERTIFICATE_ENROLLMENT",
      configuration: {},
    } as unknown as CreateCertificateProfileRequest;

    postMock.mockResolvedValue({ data: {} });
    putMock.mockResolvedValue({ data: {} });

    await createCertificateProfile(input);
    await updateCertificateProfile("prof_1", {
      name: "p",
      lifecycleStatus: "ACTIVE",
      expectedVersion: 3,
      confirmReissuance: true,
      configuration: {},
    });

    expect(postMock).toHaveBeenCalledWith(
      apiRoutes.mutation.machineIdentityProfiles.create,
      input,
    );
    expect(putMock.mock.calls[0][0]).toBe(
      apiRoutes.mutation.machineIdentityProfiles.update("prof_1"),
    );
    expect(putMock.mock.calls[0][1]).toMatchObject({ expectedVersion: 3 });
  });

  it("archives a missing profile with a DELETE at the detail route", async () => {
    await archiveCertificateProfile("prof_1");

    expect(deleteMock).toHaveBeenCalledTimes(1);
    expect(deleteMock.mock.calls[0][0]).toBe(
      apiRoutes.mutation.machineIdentityProfiles.archive("prof_1"),
    );
  });

  it("starts provider discovery for a source", async () => {
    postMock.mockResolvedValue({ data: { status: "ACCEPTED" } });
    await syncSourceProfiles("src_1");
    expect(postMock).toHaveBeenCalledWith(
      apiRoutes.mutation.machineIdentityProfiles.sourceProfilesSync("src_1"),
    );
  });

  it("lists profiles with the resolved params", async () => {
    await listCertificateProfiles({ sourceXref: "src_1" });
    expect(sentParams(getMock.mock.calls[0])).toMatchObject({
      sourceXref: "src_1",
    });
  });
});

describe("source adapters", () => {
  it("lists sources without params - the endpoint is unpaged", async () => {
    getMock.mockResolvedValue({ data: [] });
    await listDeviceSources();
    expect(getMock).toHaveBeenCalledWith(apiRoutes.query.iotDevices.sources);
  });

  it("scopes source events to one run when a correlation id is given", () => {
    expect(
      resolveDeviceSourceEventParams({ correlationId: "sync_1" }),
    ).toMatchObject({ correlationId: "sync_1" });
    expect("correlationId" in resolveDeviceSourceEventParams({})).toBe(false);
  });

  it("requests source events with the resolved params", async () => {
    await listDeviceSourceEvents("src_1", { correlationId: "sync_1", size: 5 });
    expect(sentParams(getMock.mock.calls[0])).toMatchObject({
      correlationId: "sync_1",
      size: 5,
    });
  });

  it("triggers and stops sync at their own routes", async () => {
    postMock.mockResolvedValue({ data: { status: "ACCEPTED" } });
    await triggerDeviceSourceSync("src_1");
    await stopDeviceSourceSync("src_1");

    expect(postMock.mock.calls[0][0]).toBe(
      apiRoutes.mutation.iotDevices.sourceSync("src_1"),
    );
    expect(postMock.mock.calls[1][0]).toBe(
      apiRoutes.mutation.iotDevices.sourceSyncStop("src_1"),
    );
  });
});

describe("connector and summary adapters", () => {
  it("reads the org summary", async () => {
    getMock.mockResolvedValue({ data: { totalDevices: 7 } });
    await expect(getIotSummary()).resolves.toMatchObject({ totalDevices: 7 });
    expect(getMock).toHaveBeenCalledWith(apiRoutes.query.iotDevices.summary);
  });

  it("reads CA connectors as a plain list and by id", async () => {
    getMock.mockResolvedValue({ data: [] });
    await listCaConnectors();
    await getCaConnector("ejbca-default");

    expect(getMock.mock.calls[0][0]).toBe(
      apiRoutes.query.iotDevices.caConnectors,
    );
    expect(getMock.mock.calls[1][0]).toBe(
      apiRoutes.query.iotDevices.caConnector("ejbca-default"),
    );
  });
});

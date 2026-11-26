// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { certificateCheckInUnavailableReason } from "@/lib/machine-identity/certificate-check-in";
import { INTUNE_DEVICE_CHECK_IN_PERMISSION } from "@/lib/machine-identity/backend-display";
import type {
  DeviceDetail,
  DeviceSourceDto,
} from "@/types/machine-identity-backend";

const device = {
  deviceXref: "dev_1",
  source: { sourceXref: "src_1", provider: "INTUNE" },
} as DeviceDetail;

function source(granted: boolean): DeviceSourceDto {
  return {
    sourceXref: "src_1",
    provider: "INTUNE",
    health: {
      permissions: [{ name: INTUNE_DEVICE_CHECK_IN_PERMISSION, granted }],
    },
  } as DeviceSourceDto;
}

const allowedContext = {
  canManage: true,
  linkedDeviceXref: "dev_1",
  device,
  deviceLoading: false,
  deviceFailed: false,
  source: source(true),
  sourceLoading: false,
  sourceFailed: false,
};

describe("certificate check-in availability", () => {
  it("allows a linked Intune device with the privileged operation role", () => {
    expect(certificateCheckInUnavailableReason(allowedContext)).toBeNull();
  });

  it("rejects an unmatched certificate before querying a provider", () => {
    expect(
      certificateCheckInUnavailableReason({
        ...allowedContext,
        linkedDeviceXref: undefined,
        device: undefined,
        source: undefined,
      }),
    ).toContain("linked to a device");
  });

  /**
   * The device summary is populated for an archived device now, so the gate can no longer rely on
   * a null summary to keep the action away. Without this the UI offers a check-in the backend
   * silently skips, because its device selection excludes archived rows.
   */
  it("rejects an archived device and says how to fix it", () => {
    expect(
      certificateCheckInUnavailableReason({
        ...allowedContext,
        device: { ...device, archived: true },
      }),
    ).toContain("archived");
  });

  it("rejects a non-Intune device", () => {
    expect(
      certificateCheckInUnavailableReason({
        ...allowedContext,
        device: {
          ...device,
          source: { ...device.source, provider: "JAMF" },
        },
      }),
    ).toContain("only for Microsoft Intune");
  });

  it("requires a current health report with privileged-operation consent", () => {
    expect(
      certificateCheckInUnavailableReason({
        ...allowedContext,
        source: source(false),
      }),
    ).toContain(INTUNE_DEVICE_CHECK_IN_PERMISSION);
    expect(
      certificateCheckInUnavailableReason({
        ...allowedContext,
        source: undefined,
        sourceFailed: true,
      }),
    ).toContain("health report");
  });

  it("requires the CertPing manage permission as well", () => {
    expect(
      certificateCheckInUnavailableReason({
        ...allowedContext,
        canManage: false,
      }),
    ).toContain("iot_device:manage");
  });
});

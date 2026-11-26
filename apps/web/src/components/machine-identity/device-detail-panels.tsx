// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import {
  DefinitionList,
  DetailEmptyState,
  DetailPanel,
  DynamicDataPanel,
  PanelMasonry,
} from "@/components/machine-identity/detail-panel";
import { Badge } from "@/components/ui/badge";
import {
  complianceStateLabel,
  complianceStateVariant,
  DEVICE_CLASS_LABELS,
  DEVICE_OWNERSHIP_LABELS,
  DEVICE_STATUS_DESCRIPTIONS,
  DEVICE_STATUS_LABELS,
  deviceStatusVariant,
  providerLabel,
} from "@/lib/machine-identity/backend-display";
import { humanizeConstant } from "@/lib/machine-identity/display";
import { formatDateTimeCompact } from "@/lib/utils";
import type { DeviceDetail } from "@/types/machine-identity-backend";

/** Boolean posture fields report tri-state (yes/no/unknown), not just yes/no. */
function formatTriState(value: boolean | null): string {
  if (value === null) return "Not reported";
  return value ? "Yes" : "No";
}

/**
 * Why a device has no owner on record.
 *
 * <p>The field is empty for every Intune device because CertPing's Intune
 * connector deliberately does not request user or owner data from Graph - it
 * is a scope decision, not missing data or a sync failure, and saying so stops
 * operators from re-running syncs that can never fill it.
 */
function ownerEmptyMessage(provider: string): string {
  if (provider === "INTUNE") {
    return "CertPing's Microsoft Intune connector does not request user or owner data, so no owner is recorded. Re-syncing will not change this.";
  }
  return `${providerLabel(provider)} has not reported an owner for this device.`;
}

/** Identity and ownership panels for the device detail page's "Details" tab. */
export function DeviceIdentityPanels({ device }: { device: DeviceDetail }) {
  const status = device.status;

  return (
    <>
      <DetailPanel title="Identity">
        <DefinitionList
          items={[
            {
              label: "Status",
              node: status ? (
                <span className="flex flex-col items-start gap-1">
                  <Badge variant={deviceStatusVariant(status)}>
                    {DEVICE_STATUS_LABELS[status]}
                  </Badge>
                  <span className="block text-xs text-muted-foreground">
                    {DEVICE_STATUS_DESCRIPTIONS[status]}
                  </span>
                </span>
              ) : (
                <span className="text-muted-foreground">Not recorded</span>
              ),
            },
            {
              label: "Source device ID",
              value: device.sourceDeviceId,
              monospace: true,
              copyable: true,
            },
            {
              label: "Device class",
              value: device.deviceClass
                ? (DEVICE_CLASS_LABELS[device.deviceClass] ??
                  humanizeConstant(device.deviceClass))
                : null,
            },
            { label: "Serial number", value: device.serialNumber },
            { label: "Manufacturer", value: device.manufacturer },
            { label: "Model", value: device.model },
            {
              label: "Ownership",
              value: device.ownership
                ? (DEVICE_OWNERSHIP_LABELS[device.ownership] ??
                  humanizeConstant(device.ownership))
                : null,
            },
            {
              label: "First registered",
              value: device.registeredAt
                ? formatDateTimeCompact(device.registeredAt)
                : null,
            },
            {
              label: "Last seen",
              value: device.lastSeenInSourceAt
                ? formatDateTimeCompact(device.lastSeenInSourceAt)
                : "Never",
            },
            {
              label: "Decommissioned",
              value: device.decommissionedAt
                ? formatDateTimeCompact(device.decommissionedAt)
                : null,
            },
          ]}
        />
      </DetailPanel>

      <DetailPanel title="Owner">
        {device.owner ? (
          <DefinitionList
            items={[
              { label: "Display name", value: device.owner.displayName },
              { label: "UPN", value: device.owner.upn },
              { label: "Email", value: device.owner.email },
              {
                label: "Updated",
                value: device.owner.updatedAt
                  ? formatDateTimeCompact(device.owner.updatedAt)
                  : null,
              },
            ]}
          />
        ) : (
          <DetailEmptyState
            message={ownerEmptyMessage(device.source.provider)}
          />
        )}
      </DetailPanel>
    </>
  );
}

/** Endpoint posture and connected-thing panels for the "Details" tab. */
export function DevicePosturePanels({ device }: { device: DeviceDetail }) {
  const posture = device.endpointPosture;

  return (
    <>
      <DetailPanel title="Endpoint posture">
        {posture ? (
          <DefinitionList
            items={[
              {
                label: "Operating system",
                value: posture.operatingSystem,
              },
              { label: "OS version", value: posture.osVersion },
              {
                label: "Compliance",
                node: (
                  <span className="flex flex-col items-start gap-1">
                    <Badge
                      variant={complianceStateVariant(posture.complianceState)}
                    >
                      {complianceStateLabel(posture.complianceState)}
                    </Badge>
                    {/* The raw vendor string is what an Intune admin will
                        recognize; CertPing's normalized enum is what the
                        filters use. Both matter, so both are shown. */}
                    {posture.complianceStateRaw &&
                    posture.complianceStateRaw !== posture.complianceState ? (
                      <span className="block text-xs text-muted-foreground">
                        {`Source reports "${posture.complianceStateRaw}"`}
                      </span>
                    ) : null}
                  </span>
                ),
              },
              {
                label: "Disk encrypted",
                value: formatTriState(posture.encrypted),
              },
              {
                label: "Supervised",
                value: formatTriState(posture.supervised),
              },
              { label: "Jailbroken", value: posture.jailbrokenState },
              { label: "Management agent", value: posture.managementAgent },
              { label: "Enrollment type", value: posture.enrollmentType },
              {
                label: "MDM enrolled",
                value: posture.mdmEnrolledAt
                  ? formatDateTimeCompact(posture.mdmEnrolledAt)
                  : null,
              },
              {
                label: "MDM last synced",
                value: posture.mdmLastSyncAt
                  ? formatDateTimeCompact(posture.mdmLastSyncAt)
                  : null,
              },
            ]}
          />
        ) : (
          <DetailEmptyState message="No endpoint posture reported for this device." />
        )}
      </DetailPanel>

      {device.connectedThing ? (
        <DetailPanel title="Connected thing">
          <DefinitionList
            items={[
              { label: "Thing type", value: device.connectedThing.thingType },
              {
                label: "Form factor",
                value: device.connectedThing.formFactor,
              },
              {
                label: "Attestation",
                value: device.connectedThing.attestationType,
              },
              {
                label: "Hub or account",
                value: device.connectedThing.hubOrAccountRef,
                monospace: true,
              },
              {
                label: "Connectivity",
                value: device.connectedThing.connectivityState,
              },
              {
                label: "Last connected",
                value: device.connectedThing.lastConnectedAt
                  ? formatDateTimeCompact(device.connectedThing.lastConnectedAt)
                  : null,
              },
            ]}
          />
        </DetailPanel>
      ) : null}
    </>
  );
}

/**
 * Everything the source reported that CertPing does not model itself.
 *
 * <p>These payloads are provider-shaped and were previously fetched on every
 * device detail request and then dropped on the floor. They are the fields an
 * operator needs when correlating a certificate back to an Intune object, so
 * they get a tab of their own rather than either cluttering the summary or
 * being discarded.
 */
export function DevicePlatformDataPanels({ device }: { device: DeviceDetail }) {
  const vendorLabel = providerLabel(device.source.provider);

  return (
    <PanelMasonry>
      <DynamicDataPanel
        title="Source identifiers"
        description={`Identifiers ${vendorLabel} uses for this device.`}
        value={device.sourceIdentifiers}
        emptyMessage="No additional identifiers were reported."
      />
      <DynamicDataPanel
        title="Platform attributes"
        description={
          device.providerData?.updatedAt
            ? `Allowlisted ${vendorLabel} attributes, updated ${formatDateTimeCompact(device.providerData.updatedAt)}.`
            : `Allowlisted ${vendorLabel} attributes.`
        }
        value={device.providerData?.attributes}
        emptyMessage="No platform attributes were reported."
      />
      <DynamicDataPanel
        title="Vendor posture attributes"
        description="Posture facts reported alongside the normalized fields."
        value={device.endpointPosture?.vendorAttributes}
        emptyMessage="No vendor posture attributes were reported."
      />
      <DynamicDataPanel
        title="Source connection"
        description="Non-secret configuration advertised by the agent for this source."
        value={device.source.configurationMetadata}
        emptyMessage="This source advertised no configuration metadata."
      />
    </PanelMasonry>
  );
}

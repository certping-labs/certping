// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.enums;

/**
 * Optional detail tables a device may have a row in.
 *
 * <p>A device gets a row only in the facets that apply to it. Which ones a platform produces is
 * declared by its adapter rather than inferred from {@link DeviceClass}, which is only a display
 * hint — an OT sensor in a cloud IoT registry is genuinely more than one thing at once.
 *
 * <p>An industrial-asset facet lands here when OT equipment does; like the others it is one
 * table plus one writer, with no change to the upsert engine.
 */
public enum DeviceFacet {

    /** {@code iot_device_endpoint_posture} — MDM/UEM sources: Intune, Jamf, Workspace ONE. */
    ENDPOINT_POSTURE,

    /** {@code iot_device_connected_thing} — cloud IoT registries: AWS IoT, Azure IoT. */
    CONNECTED_THING,

    /** {@code iot_device_owner} — reserved for a later, explicitly opted-in PII design. */
    OWNER
}

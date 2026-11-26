// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.dto.request;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Cloud IoT registry attributes, when the source is one.
 *
 * <p>Grouped rather than flattened onto {@link DeviceIdentityPayload}: they apply to AWS IoT
 * and Azure IoT only, and an MDM leaves the whole object null. A device with this block gets an
 * {@code iot_device_connected_thing} row; one without does not.
 *
 * @param attestationType   X509 | TPM | SYMMETRIC_KEY — how the device proved identity at
 *                          registration. Not a certificate we issued; recorded, not verified.
 * @param formFactor        MCU | MPU | GATEWAY. An MPU renews its own certificates and keeps a
 *                          clock; an MCU frequently does neither, and certificate policy later
 *                          depends on knowing which.
 */
public record ConnectedThingAttributes(
        String attestationType,
        String hubOrAccountRef,
        String thingType,
        String formFactor,
        String connectivityState,
        OffsetDateTime lastConnectedAt,
        Map<String, Object> customAttributes
) {}

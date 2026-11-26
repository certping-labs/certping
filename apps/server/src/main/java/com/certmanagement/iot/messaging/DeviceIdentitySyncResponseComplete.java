// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Terminal message for a sync run ({@code DEVICE_IDENTITY_SYNC_RESPONSE_COMPLETE}).
 *
 * <p>Mirrors the agent's {@code DeviceIdentitySyncCompleteMessage}.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeviceIdentitySyncResponseComplete {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String syncXref;
    private String mode;
    private int totalDevices;
    private int totalBatches;
    private String completedAt;
}

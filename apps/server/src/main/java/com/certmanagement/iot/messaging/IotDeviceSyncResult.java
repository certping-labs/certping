// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Inbound from cert-agent-outbound with MessageType={@code IOT_DEVICE_SYNC_RESPONSE}: the outcome
 * of one {@code syncDevice} nudge. Best-effort — {@code NUDGE_SENT} means Intune accepted the
 * check-in request, never that the certificate renewed.
 *
 * <p>Field names match the agent's outbound {@code IotDeviceSyncResult}.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class IotDeviceSyncResult {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String deviceXref;
    private List<String> certificateXrefs;
    private String managedDeviceId;

    /** NUDGE_SENT | INTUNE_REJECTED | INTUNE_UNAVAILABLE | SKIPPED_UNSUPPORTED. */
    private String outcome;

    private Integer httpStatus;
    private String errorCode;
    private String errorMessage;
    private String respondedAt;
}

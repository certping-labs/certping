// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Outcome of a renewal-nudge (Intune {@code syncDevice}) attempt, reported back to the server.
 * Best-effort: {@code NUDGE_SENT} means Intune accepted the check-in request, not that the device
 * checked in or renewed. Metadata only.
 */
@Data
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class IotDeviceSyncResponse {
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

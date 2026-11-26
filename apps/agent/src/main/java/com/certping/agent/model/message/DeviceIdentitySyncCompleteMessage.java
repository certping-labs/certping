// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Terminal message for a sync run.
 *
 * <p>{@code mode} is echoed back because the server permits orphan detection only after a
 * validated full run. The server uses its own committed {@code startedAt} timestamp as the
 * orphan cutoff; the agent does not supply that boundary.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceIdentitySyncCompleteMessage {
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

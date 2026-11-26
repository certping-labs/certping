// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.util.List;

/** One page of devices on the way back to the server. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceIdentitySyncResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    private String syncXref;
    private int batchIndex;
    private String batchChecksum;
    private List<DeviceIdentityEntry> devices;
    private String respondedAt;
}

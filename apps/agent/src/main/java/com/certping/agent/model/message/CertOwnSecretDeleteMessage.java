// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertOwnSecretDeleteMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String certSecretHandle;
    private String reason;
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertSecretDeleteMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String certSecretHandle;
    private String requestedAt;
}

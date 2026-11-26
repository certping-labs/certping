// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.discovery;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Value;

import java.time.OffsetDateTime;

@Value
@Jacksonized
@Builder(toBuilder = true)
public class DiscoveryRunResponse {

    Long configId;
    String status;
    String message;
    String requestId;
    String targetType;
    String credentialXref;
    OffsetDateTime startedAt;
    OffsetDateTime completedAt;
    /**
     * The scopes the last run could not read, from discovery_scan.failed_scopes: each
     * {scopeType, scopeId, errorCode, message}. Empty when it read everything or has not finished.
     */
    @Builder.Default
    java.util.List<com.certmanagement.messaging.model.DiscoveryFailedScope> failedScopes = java.util.List.of();
}

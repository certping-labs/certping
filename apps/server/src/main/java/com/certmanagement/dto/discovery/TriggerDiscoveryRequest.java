// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.discovery;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Request body for POST /api/v1/discovery/trigger.
 *
 * <p>The caller specifies which deployment credential to use for authenticating with
 * the target cloud provider. The credential's KV path is resolved server-side so
 * that raw secret URIs are never sent over the wire from the frontend.
 */
@Data
public class TriggerDiscoveryRequest {

    /**
     * The target type to scan (e.g. "AWS_ACM").
     * Must match a value in the agent's TargetType enum.
     */
    @NotBlank(message = "targetType is required")
    private String targetType;

    /**
     * Xref of an existing deployment credential reference.
     * The credential's KV path is used by the agent to authenticate with the cloud provider.
     */
    @NotBlank(message = "credentialXref is required")
    private String credentialXref;
}

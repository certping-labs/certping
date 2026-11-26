// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * One part of a discovery scan the agent could not read, as the agent's
 * {@code DiscoveryFailedScope} sends it in {@code failedScopes} of a discovery result.
 *
 * <p>{@code scopeType} is one of {@link #AWS_ACCOUNT}, {@link #AWS_REGION}, {@link #AZURE_VAULT},
 * {@link #K8S_NAMESPACE}, {@link #K8S_CLUSTER}. {@code scopeId} formats: AWS_ACCOUNT
 * {@code 123456789012}; AWS_REGION {@code 123456789012/us-east-1} (or just the region); AZURE_VAULT
 * the vault name; K8S_NAMESPACE the namespace; K8S_CLUSTER the cluster name.
 *
 * <p>Kept as strings so a scope type this server does not know still arrives; such a scope covers
 * every certificate of the scan (see {@code FailedScopes#covers}).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class DiscoveryFailedScope {

    public static final String AWS_ACCOUNT = "AWS_ACCOUNT";
    public static final String AWS_REGION = "AWS_REGION";
    public static final String AZURE_VAULT = "AZURE_VAULT";
    public static final String K8S_NAMESPACE = "K8S_NAMESPACE";
    public static final String K8S_CLUSTER = "K8S_CLUSTER";

    private String scopeType;
    private String scopeId;
    private String errorCode;
    private String message;
}

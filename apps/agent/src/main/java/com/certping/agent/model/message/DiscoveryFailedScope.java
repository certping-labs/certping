// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import lombok.Builder;
import lombok.Value;

/**
 * One part of a discovery scan that the agent could not read, such as an AWS account the member
 * role could not be assumed in, or a Kubernetes namespace whose Secrets are forbidden.
 *
 * <p>The server must leave stored certificates in a failed scope unchanged (never mark them
 * MISSING), because the agent did not see them.
 *
 * <p>{@code scopeId} formats: AWS_ACCOUNT {@code 123456789012}; AWS_REGION
 * {@code 123456789012/us-east-1}; AZURE_VAULT the vault name; K8S_NAMESPACE the namespace;
 * K8S_CLUSTER the cluster name.
 */
@Value
@Builder
public class DiscoveryFailedScope {

    /** Kinds of scope a discovery scan can fail on. Serialized by name. */
    public enum ScopeType {
        AWS_ACCOUNT,
        AWS_REGION,
        AZURE_VAULT,
        K8S_NAMESPACE,
        K8S_CLUSTER
    }

    ScopeType scopeType;
    String scopeId;
    String errorCode;
    String message;

    public static DiscoveryFailedScope of(ScopeType scopeType, String scopeId, String errorCode, String message) {
        return DiscoveryFailedScope.builder()
                .scopeType(scopeType)
                .scopeId(scopeId)
                .errorCode(errorCode)
                .message(message)
                .build();
    }
}

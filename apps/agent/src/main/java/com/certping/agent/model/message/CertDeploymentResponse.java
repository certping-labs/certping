// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.TargetType;
import lombok.Builder;
import lombok.Data;

/**
 * Outbound message — agent → certping (cert-agent-outbound).
 *
 * <p>The {@code MessageType} is set as an <em>application property</em> by
 * {@link com.certping.agent.listener.AgentMessageSender} — it is NOT a JSON body field.
 * The server routes on the application property, not the body, so no {@code messageType}
 * field is needed here.
 */
@Data
@Builder
public class CertDeploymentResponse {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private TargetType targetType;
    private String status;
    private String targetResourceId;
    private String respondedAt;

    /**
     * Per-domain config to be persisted by the server after the first deployment for a domain.
     * Null on all subsequent deployments (the server already holds the config).
     * AWS: {"arn":"arn:aws:acm:..."} | Azure KV: {"certificateName":"example-com"}
     */
    private String configJson;
}

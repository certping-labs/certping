// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.model.enums.MessageType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumSet;
import java.util.Set;

/**
 * Defense-in-depth: even though the gateway hands the agent only its own organization's
 * commands, we still verify the payload's organizationId matches the configured org. A misrouted publish on the server side would otherwise
 * deliver another tenant's work to this pod.
 */
@Slf4j
@Component
public class AgentInboundMessageRouting {

    // Read on every call: over the HTTPS gateway the organization can be learned from the token after
    // startup, when the server first answers.
    private final AgentProperties properties;
    private final Set<MessageType> organizationScopedMessageTypes;

    public AgentInboundMessageRouting(AgentProperties properties) {
        this.properties = properties;
        this.organizationScopedMessageTypes = EnumSet.of(
                MessageType.CERT_ISSUANCE,
                MessageType.CERT_RENEWAL,
                MessageType.CERT_DEPLOYMENT,
                MessageType.CERT_MANUAL_TXT_REQUEST,
                MessageType.CERT_MANUAL_DNS_VALIDATE,
                MessageType.CERT_REVOCATION_COMMAND,
                MessageType.CERT_OWN_SECRET_DELETE,
                MessageType.CERT_SECRET_DELETE_COMMAND,
                MessageType.AGENT_HEARTBEAT_CADENCE_UPDATE,
                MessageType.AGENT_DEEP_HEALTH_CHECK,
                MessageType.DEVICE_IDENTITY_SYNC_COMMAND,
                MessageType.IOT_DEVICE_SYNC_COMMAND,
                MessageType.IOT_CERTIFICATE_REVOCATION_COMMAND,
                MessageType.IOT_INTUNE_REVOCATION_POLL_COMMAND,
                MessageType.IOT_INTUNE_REVOCATION_UPLOAD_COMMAND,
                MessageType.IOT_CERTIFICATE_PROFILE_COMMAND,
                MessageType.IOT_CERTIFICATE_PROFILE_SYNC_COMMAND
        );

        log.info("Inbound routing configured organizationId={}", configuredOrganizationId());
    }

    public boolean requiresOrganizationMatch(MessageType messageType) {
        return organizationScopedMessageTypes.contains(messageType) && configuredOrganizationId() != null;
    }

    public boolean matchesConfiguredOrganization(String messageOrganizationId) {
        String configured = configuredOrganizationId();
        return configured != null && configured.equals(normalize(messageOrganizationId));
    }

    public String configuredOrganizationId() {
        return normalize(properties.getOrganizationId());
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isBlank() ? null : trimmed;
    }
}

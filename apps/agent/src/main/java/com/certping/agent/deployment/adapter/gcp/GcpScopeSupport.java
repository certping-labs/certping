// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.cloud.gcp.GcpAuthMode;
import com.certping.agent.deployment.cloud.gcp.GcpAuthScope;
import com.certping.agent.deployment.cloud.gcp.GcpAuthSecret;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.GcpCertificateManagerDeploymentCredential;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared parsing helpers used by all GCP adapters to convert wire JSON into the
 * cloud-resolver's typed inputs.
 */
public final class GcpScopeSupport {

    private GcpScopeSupport() {}

    public static GcpAuthMode parseAuthMode(String authMode, String context) {
        if (authMode == null || authMode.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credentialScopeJson missing 'authMode'");
        }
        try {
            return GcpAuthMode.valueOf(authMode.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " unknown GCP authMode: '" + authMode + "'");
        }
    }

    public static GcpAuthScope toAuthScope(String projectId, String location, String impersonateSa) {
        return new GcpAuthScope(projectId, location, impersonateSa);
    }

    public static GcpAuthSecret parseKvSecret(ObjectMapper objectMapper, String credRaw, String context) {
        if (credRaw == null || credRaw.isBlank()) {
            return GcpAuthSecret.empty();
        }
        try {
            GcpCertificateManagerDeploymentCredential parsed = objectMapper.readValue(
                    credRaw, GcpCertificateManagerDeploymentCredential.class);
            // serviceAccountKeyJson is typed as JsonNode so the KV can store it as the natural
            // nested-object shape (the same shape Google ships when you download a service-account
            // key file). Normalize to a JSON string here because GoogleCredentials.fromStream
            // expects the raw service-account JSON bytes. If the KV happens to store it as a JSON
            // string instead, JsonNode.textValue() returns that string directly.
            String serviceAccountKeyJsonString = serializeServiceAccountKeyJson(
                    objectMapper, parsed.getServiceAccountKeyJson(), context);
            return new GcpAuthSecret(serviceAccountKeyJsonString, parsed.getServiceAccountKeyJsonBase64());
        } catch (PermanentAgentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + context + " KV secret JSON: " + ex.getMessage(), ex);
        }
    }

    private static String serializeServiceAccountKeyJson(ObjectMapper objectMapper,
                                                          JsonNode node, String context) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        // Stringified form: KV stored the value as `"serviceAccountKeyJson": "{...}"`.
        if (node.isString()) {
            String text = node.asString();
            return (text == null || text.isBlank()) ? null : text;
        }
        // Nested-object form: KV stored the natural shape `"serviceAccountKeyJson": { ... }`.
        if (node.isObject()) {
            try {
                return objectMapper.writeValueAsString(node);
            } catch (Exception ex) {
                throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                        "Failed to serialize " + context + " serviceAccountKeyJson object: "
                                + ex.getMessage(), ex);
            }
        }
        throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                context + " serviceAccountKeyJson must be a JSON object or a JSON string, got: "
                        + node.getNodeType());
    }
}

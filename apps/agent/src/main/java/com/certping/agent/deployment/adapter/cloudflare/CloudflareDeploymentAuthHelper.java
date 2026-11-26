// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.cloudflare;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.CloudflareEdgeDeploymentCredential;
import tools.jackson.databind.ObjectMapper;

public final class CloudflareDeploymentAuthHelper {

    private CloudflareDeploymentAuthHelper() {}

    public static CloudflareEdgeDeploymentCredential parseKvSecret(ObjectMapper objectMapper, String raw) {
        try {
            return objectMapper.readValue(raw, CloudflareEdgeDeploymentCredential.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse Cloudflare KV secret JSON: " + e.getMessage(), e);
        }
    }

    public static String requireField(String name, String value, String context) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " missing required field: " + name);
        }
        return value;
    }

    public static String bearerToken(String apiToken) {
        return "Bearer " + requireField("apiToken", apiToken, "Cloudflare KV secret").trim();
    }
}

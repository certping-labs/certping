// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.credential.AwsDeploymentCredential;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared parsing helpers used by all AWS adapters to convert wire JSON into the
 * cloud-resolver's typed inputs.
 */
public final class AwsScopeSupport {

    private AwsScopeSupport() {}

    public static AwsAuthMode parseAuthMode(String authMode, String context) {
        if (authMode == null || authMode.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credentialScopeJson missing 'authMode'");
        }
        try {
            return AwsAuthMode.valueOf(authMode.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " unknown AWS authMode: '" + authMode + "'");
        }
    }

    public static AwsAuthScope toAuthScope(String region, String roleArn, String externalId) {
        return new AwsAuthScope(region, roleArn, externalId);
    }

    public static AwsAuthSecret parseKvSecret(ObjectMapper objectMapper, String credRaw, String context) {
        if (credRaw == null || credRaw.isBlank()) {
            return AwsAuthSecret.empty();
        }
        try {
            AwsDeploymentCredential parsed = objectMapper.readValue(credRaw, AwsDeploymentCredential.class);
            return new AwsAuthSecret(parsed.getAccessKeyId(), parsed.getSecretAccessKey());
        } catch (Exception ex) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + context + " KV secret JSON: " + ex.getMessage(), ex);
        }
    }
}

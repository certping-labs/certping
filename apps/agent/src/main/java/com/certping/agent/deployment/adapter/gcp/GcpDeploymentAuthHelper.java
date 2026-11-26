// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.GoogleCredentials;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class GcpDeploymentAuthHelper {

    public static final String CLOUD_PLATFORM_SCOPE =
            "https://www.googleapis.com/auth/cloud-platform";

    private GcpDeploymentAuthHelper() {}

    public static <T> T parseCredential(ObjectMapper objectMapper, String raw, Class<T> type, String context) {
        try {
            return objectMapper.readValue(raw, type);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + context + " credential JSON: " + e.getMessage(), e);
        }
    }

    public static void requireField(String name, String value, String context) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential missing required field: " + name);
        }
    }

    public static GoogleCredentials buildCredentials(String serviceAccountJson,
                                                     String serviceAccountJsonBase64,
                                                     String context) {
        byte[] jsonBytes = resolveServiceAccountBytes(serviceAccountJson, serviceAccountJsonBase64, context);
        try {
            GoogleCredentials creds = jsonBytes == null
                    ? GoogleCredentials.getApplicationDefault()
                    : GoogleCredentials.fromStream(new ByteArrayInputStream(jsonBytes));

            if (creds.createScopedRequired()) {
                return creds.createScoped(CLOUD_PLATFORM_SCOPE);
            }
            return creds;

        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_GCP_AUTH_FAILED",
                    context + " failed to build Google credentials: " + e.getMessage(), e);
        }
    }

    private static byte[] resolveServiceAccountBytes(String serviceAccountJson,
                                                     String serviceAccountJsonBase64,
                                                     String context) {
        if (serviceAccountJson != null && !serviceAccountJson.isBlank()) {
            return serviceAccountJson.getBytes(StandardCharsets.UTF_8);
        }
        if (serviceAccountJsonBase64 == null || serviceAccountJsonBase64.isBlank()) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(serviceAccountJsonBase64);
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential serviceAccountKeyJsonBase64 is not valid Base64", e);
        }
    }
}

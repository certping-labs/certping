// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.exception.PermanentAgentException;

import java.util.Locale;

/**
 * Supported Kubernetes authentication providers for deployment operations.
 */
public enum KubernetesAuthProvider {
    AWS,
    AZURE,
    GCP,
    SA_TOKEN,
    SA_INCLUSTER;

    public static KubernetesAuthProvider fromConfigValue(String value) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Kubernetes deployment configJson must include authProvider");
        }

        String normalized = value.trim().toUpperCase(Locale.ROOT);
        try {
            return KubernetesAuthProvider.valueOf(normalized);
        } catch (IllegalArgumentException e) {
            throw new PermanentAgentException("DEPLOY_K8S_CONFIG_INVALID",
                    "Unsupported Kubernetes authProvider '" + value +
                            "'. Supported values: AWS, AZURE, GCP, SA_TOKEN, SA_INCLUSTER");
        }
    }
}

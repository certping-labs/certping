// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.azure;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AzureCloudCredentialResolverTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final String CLIENT = "22222222-2222-2222-2222-222222222222";

    private final AzureCloudCredentialResolver resolver = new AzureCloudCredentialResolver();

    @Test
    void workloadIdentityWithoutClientId_reportsMissingClientId() {
        AzureAuthScope scope = new AzureAuthScope(TENANT, null, null, null);

        assertThatThrownBy(() -> resolver.resolve(AzureAuthMode.WORKLOAD_IDENTITY, scope, null, "Azure KV"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("clientId")
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AZURE_CLIENT_ID_MISSING"));
    }

    @Test
    void servicePrincipalWithoutClientId_reportsMissingClientId() {
        AzureAuthScope scope = new AzureAuthScope(TENANT, null, null, null);

        assertThatThrownBy(() -> resolver.resolve(AzureAuthMode.SERVICE_PRINCIPAL, scope,
                new AzureAuthSecret(" ", "secret"), "Azure KV"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AZURE_CLIENT_ID_MISSING"));
    }

    @Test
    void workloadIdentityWithScopeClientId_buildsCredential() {
        AzureAuthScope scope = new AzureAuthScope(TENANT, null, CLIENT, "/var/run/token");

        assertThat(resolver.resolve(AzureAuthMode.WORKLOAD_IDENTITY, scope, null, "Azure KV")).isNotNull();
    }
}

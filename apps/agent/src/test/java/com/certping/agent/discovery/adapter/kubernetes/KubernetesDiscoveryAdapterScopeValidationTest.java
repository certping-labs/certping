// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertDiscoveryMessage;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KubernetesDiscoveryAdapterScopeValidationTest {

    @Test
    void discover_rejectsOmittedNamespaces() {
        KubernetesDiscoveryAdapter adapter = adapter();
        CertDiscoveryMessage message = message("""
                {"authProvider":"SA_TOKEN","clusterName":"prod-aks"}
                """);

        assertThatThrownBy(() -> adapter.discover(message))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("scope must include namespaces");
    }

    @Test
    void discover_rejectsClusterNameThatWouldCorruptResourceId() {
        KubernetesDiscoveryAdapter adapter = adapter();
        CertDiscoveryMessage message = message("""
                {"authProvider":"SA_TOKEN","clusterName":"prod/aks","namespaces":["frontend"]}
                """);

        assertThatThrownBy(() -> adapter.discover(message))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("clusterName must be at most 253 characters");
    }

    @Test
    void discover_rejectsBlankNamespaceEntry() {
        KubernetesDiscoveryAdapter adapter = adapter();
        CertDiscoveryMessage message = message("""
                {"authProvider":"SA_TOKEN","clusterName":"prod-aks","namespaces":[" "]}
                """);

        assertThatThrownBy(() -> adapter.discover(message))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("namespaces entries must be non-empty");
    }

    @Test
    void discover_rejectsAllNamespacesArrayForm() {
        KubernetesDiscoveryAdapter adapter = adapter();
        CertDiscoveryMessage message = message("""
                {"authProvider":"SA_TOKEN","clusterName":"prod-aks","namespaces":["all_namespaces"]}
                """);

        assertThatThrownBy(() -> adapter.discover(message))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("Use string form");
    }

    private KubernetesDiscoveryAdapter adapter() {
        return new KubernetesDiscoveryAdapter(
                null,
                null,
                null,
                null,
                null,
                null,
                JsonMapper.builderWithJackson2Defaults().build());
    }

    private CertDiscoveryMessage message(String credentialScopeJson) {
        CertDiscoveryMessage message = new CertDiscoveryMessage();
        message.setCredentialScopeJson(credentialScopeJson);
        return message;
    }
}

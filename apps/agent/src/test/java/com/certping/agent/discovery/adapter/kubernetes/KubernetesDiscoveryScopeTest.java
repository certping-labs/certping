// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KubernetesDiscoveryScopeTest {

    @Test
    void allNamespacesString_selectsClusterWideMode() throws Exception {
        KubernetesDiscoveryScope scope = parse("""
                {"authProvider":"SA_TOKEN","clusterName":"prod-aks","namespaces":"all_namespaces"}
                """);

        assertThat(scope.allNamespaces()).isTrue();
        assertThat(scope.explicitNamespaces()).isEmpty();
    }

    @Test
    void explicitNamespaceArray_selectNamespaceScopedMode() throws Exception {
        KubernetesDiscoveryScope scope = parse("""
                {
                  "authProvider":"SA_TOKEN",
                  "clusterName":"prod-aks",
                  "namespaces":["payments","frontend","frontend"]
                }
                """);

        assertThat(scope.allNamespaces()).isFalse();
        assertThat(scope.explicitNamespaces()).containsExactly("frontend", "payments");
    }

    @Test
    void allNamespacesArrayForm_isRejected() {
        assertThatThrownBy(() -> parse("""
                {"authProvider":"SA_TOKEN","clusterName":"prod-aks","namespaces":["all_namespaces"]}
                """))
                .isInstanceOf(com.certping.agent.exception.PermanentAgentException.class)
                .hasMessageContaining("Use string form");
    }

    @Test
    void explicitNamespaceString_isRejected() {
        assertThatThrownBy(() -> parse("""
                {"authProvider":"SA_TOKEN","clusterName":"prod-aks","namespaces":"frontend"}
                """))
                .isInstanceOf(com.certping.agent.exception.PermanentAgentException.class)
                .hasMessageContaining("use an array for explicit namespaces");
    }

    private KubernetesDiscoveryScope parse(String json) throws Exception {
        return KubernetesDiscoveryScope.fromJson(JsonMapper.builderWithJackson2Defaults().build().readTree(json));
    }
}

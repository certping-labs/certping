// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.deployment.adapter.kubernetes.KubernetesApiClientFactory;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesAuthService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertDiscoveryMessage;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link KubernetesDiscoveryAdapter}'s scope-parse and scope-validate paths.
 * <p>
 * The full {@code discover()} path requires a working {@link io.kubernetes.client.openapi.ApiClient}
 * and seven collaborators; those are covered end-to-end in the integration suite. This suite
 * exercises the pre-flight guards that reject malformed or unsafe scope JSON, which are the paths
 * responsible for the class's low unit-line coverage — they run before any collaborator is touched.
 */
@ExtendWith(MockitoExtension.class)
class KubernetesDiscoveryAdapterTest {

    @Mock private KubernetesAuthService authService;
    @Mock private KubernetesApiClientFactory apiClientFactory;
    @Mock private KubernetesInventoryClient inventoryClient;
    @Mock private KubernetesCustomResourceScanner customResourceScanner;
    @Mock private KubernetesCertificateParser certificateParser;
    @Mock private KubernetesUsageMapper usageMapper;

    private KubernetesDiscoveryAdapter adapter;

    @BeforeEach
    void setUp() {
        adapter = new KubernetesDiscoveryAdapter(authService, apiClientFactory, inventoryClient,
                customResourceScanner, certificateParser, usageMapper, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void discover_nullScopeJson_throwsInvalid() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson(null);

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"))
                .hasMessageContaining("authProvider");
    }

    @Test
    void discover_blankScopeJson_throwsInvalid() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson("   ");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"));
    }

    @Test
    void discover_unparseableScopeJson_wrapsAsInvalid() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson("this-is-not-json");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"));
    }

    @Test
    void discover_scopeMissingNamespacesField_throwsInvalidScope() {
        // KubernetesDiscoveryScope requires a namespaces field — a scope with only authProvider
        // and clusterName throws at fromJson (surfaced as DISCOVERY_K8S_SCOPE_INVALID by the
        // parseScope catch block).
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson(
                "{\"authProvider\":\"AWS\",\"clusterName\":\"cluster1\"}");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"));
    }

    @Test
    void discover_scopeMissingClusterName_throwsClusterNameRequired() {
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson(
                "{\"authProvider\":\"AWS\",\"namespaces\":\"all_namespaces\"}");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"))
                .hasMessageContaining("clusterName");
    }

    @Test
    void discover_scopeClusterNameTooLong_throwsInvalid() {
        // 254 char cluster name — over the 253 limit.
        String longName = "a".repeat(254);
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson(
                "{\"authProvider\":\"AWS\",\"clusterName\":\"" + longName + "\",\"namespaces\":\"all_namespaces\"}");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"))
                .hasMessageContaining("253");
    }

    @Test
    void discover_scopeClusterNameHasBadChars_throwsInvalid() {
        // Slash is not in the safe set [A-Za-z0-9._-].
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson(
                "{\"authProvider\":\"AWS\",\"clusterName\":\"bad/name\",\"namespaces\":\"all_namespaces\"}");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_K8S_SCOPE_INVALID"));
    }

    @Test
    void discover_scopeAuthProviderUnsupported_throwsInvalid() {
        // fromConfigValue rejects unknown auth providers with a PermanentAgentException that
        // parseScope's catch(PermanentAgentException) re-throws.
        CertDiscoveryMessage msg = new CertDiscoveryMessage();
        msg.setCredentialScopeJson(
                "{\"authProvider\":\"MAGIC_AUTH\",\"clusterName\":\"cluster1\",\"namespaces\":\"all_namespaces\"}");

        assertThatThrownBy(() -> adapter.discover(msg))
                .isInstanceOf(PermanentAgentException.class);
    }
}

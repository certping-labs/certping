// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import io.kubernetes.client.openapi.ApiException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KubernetesDiscoveryErrorTranslatorTest {

    @Test
    void translate_forbiddenResponse_doesNotExposeUpstreamBody() {
        ApiException apiException = new ApiException(
                403,
                "Forbidden",
                null,
                "{\"token\":\"sensitive-token\",\"message\":\"denied\"}");

        RuntimeException translated = KubernetesDiscoveryErrorTranslator.translate(
                "DISCOVERY_K8S_DENIED", "list Kubernetes Secrets for discovery namespace=team-a", apiException);

        assertThat(translated).isInstanceOf(PermanentAgentException.class);
        assertThat(translated.getMessage())
                .isEqualTo("Kubernetes certificate discovery was denied by Kubernetes API authorization (HTTP 403). "
                        + "Grant the discovery identity read access to the requested Kubernetes resources.")
                .doesNotContain("sensitive-token", "team-a", "{", "}");
    }

    @Test
    void translate_namespaceListForbidden_addsClusterScopeRbacHint() {
        RuntimeException translated = KubernetesDiscoveryErrorTranslator.translate(
                "DISCOVERY_K8S_NAMESPACE_LIST_DENIED",
                "list Kubernetes namespaces for discovery",
                new ApiException(403, "Forbidden"));

        assertThat(translated)
                .isInstanceOf(PermanentAgentException.class)
                .hasMessage("Kubernetes certificate discovery could not list namespaces (HTTP 403). "
                        + "Grant the discovery identity permission to list Namespaces cluster-wide, "
                        + "or send explicit namespaces.");
    }

    @Test
    void translate_secretListForbidden_usesSafeCertificateSourceMessage() {
        RuntimeException translated = KubernetesDiscoveryErrorTranslator.translate(
                "DISCOVERY_K8S_SECRET_LIST_FAILED",
                "list Kubernetes Secrets for discovery namespace=team-a",
                new ApiException(403, "Forbidden"));

        assertThat(translated)
                .isInstanceOf(PermanentAgentException.class)
                .hasMessage("Kubernetes certificate discovery could not list TLS Secrets (HTTP 403). "
                        + "Grant the discovery identity permission to list Secrets in the requested namespace(s).");
    }

    @Test
    void translate_serverFailure_isTransient() {
        RuntimeException translated = KubernetesDiscoveryErrorTranslator.translate(
                "DISCOVERY_K8S_FAILED", "list Kubernetes Pods", new ApiException(503, "Unavailable"));

        assertThat(translated).isInstanceOf(TransientAgentException.class);
    }
}

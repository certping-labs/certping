// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.model.message.KubernetesCertificateData;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class KubernetesParsedCertificateTest {

    private static final KubernetesCertificateMetadata METADATA = new KubernetesCertificateMetadata(
            "app.example.com", "RSA", "SHA256withRSA", "2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z",
            "CN=Issuer", "0a1b", "ACTIVE", "CN=app.example.com", List.of(), "digitalSignature", "serverAuth");

    @Test
    void toEntry_carriesTheSecretAndItsMetadata() {
        V1Secret secret = new V1Secret().type("kubernetes.io/tls")
                .metadata(new V1ObjectMeta().namespace("shop").name("app-tls").uid("u-1").resourceVersion("7"));
        KubernetesParsedCertificate parsed =
                KubernetesParsedCertificate.fromSecret("prod", secret, null, "AA:BB", List.of());
        KubernetesCertificateData data = KubernetesCertificateData.builder().clusterName("prod").build();

        DiscoveredCertEntry entry = parsed.toEntry(data, METADATA, List.of("Ingress/shop/web"));

        assertThat(entry.getResourceId()).isEqualTo("k8s://prod/shop/secrets/app-tls");
        assertThat(entry.getDomain()).isEqualTo("app.example.com");
        assertThat(entry.getCertType()).isEqualTo("KUBERNETES_TLS_SECRET");
        assertThat(entry.getInUseBy()).containsExactly("Ingress/shop/web");
        assertThat(entry.getSanDomains()).isNull();
        assertThat(entry.getExtendedKeyUsage()).isEqualTo("serverAuth");
        assertThat(entry.getKubernetesData()).isSameAs(data);
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.messaging.model.DiscoveryFailedScope;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Which stored certificates a failed scope covers, by their resourceId. */
class FailedScopesTest {

    private static final String ACM = "arn:aws:acm:us-east-1:111111111111:certificate/abc";
    private static final String KV = "https://prod-vault.vault.azure.net/certificates/web/123";
    private static final String K8S = "k8s://lab/payments/secrets/tls";

    @Test
    void anAwsAccountCoversItsCertificatesInEveryRegion() {
        assertThat(FailedScopes.covers(scope("AWS_ACCOUNT", "111111111111"), ACM)).isTrue();
        assertThat(FailedScopes.covers(scope("AWS_ACCOUNT", "222222222222"), ACM)).isFalse();
    }

    @Test
    void anAwsRegionCoversOneAccountsRegionOrTheRegionAlone() {
        assertThat(FailedScopes.covers(scope("AWS_REGION", "111111111111/us-east-1"), ACM)).isTrue();
        assertThat(FailedScopes.covers(scope("AWS_REGION", "111111111111/eu-west-1"), ACM)).isFalse();
        assertThat(FailedScopes.covers(scope("AWS_REGION", "222222222222/us-east-1"), ACM)).isFalse();
        assertThat(FailedScopes.covers(scope("AWS_REGION", "us-east-1"), ACM)).isTrue();
    }

    @Test
    void aVaultNamespaceAndClusterCoverTheirOwn() {
        assertThat(FailedScopes.covers(scope("AZURE_VAULT", "prod-vault"), KV)).isTrue();
        assertThat(FailedScopes.covers(scope("AZURE_VAULT", "PROD-VAULT"), KV)).isTrue();
        assertThat(FailedScopes.covers(scope("AZURE_VAULT", "dev-vault"), KV)).isFalse();
        assertThat(FailedScopes.covers(scope("K8S_NAMESPACE", "payments"), K8S)).isTrue();
        assertThat(FailedScopes.covers(scope("K8S_NAMESPACE", "web"), K8S)).isFalse();
        assertThat(FailedScopes.covers(scope("K8S_CLUSTER", "lab"), K8S)).isTrue();
        assertThat(FailedScopes.covers(scope("K8S_CLUSTER", "prod"), K8S)).isFalse();
        assertThat(FailedScopes.covers(scope("K8S_NAMESPACE", "payments"), ACM)).isFalse();
    }

    @Test
    void anUnknownTypeABlankIdOrAnUnknownCertificateCoversEverything() {
        assertThat(FailedScopes.covers(scope("GCP_PROJECT", "p"), ACM)).isTrue();
        assertThat(FailedScopes.covers(scope("AWS_ACCOUNT", " "), ACM)).isTrue();
        assertThat(FailedScopes.covers(scope("AWS_ACCOUNT", "111111111111"), null)).isTrue();
    }

    @Test
    void scopesMergeWithoutRepeatsAndRoundTripThroughStorage() {
        List<DiscoveryFailedScope> merged = FailedScopes.merge(
                List.of(scope("K8S_NAMESPACE", "a"), scope("K8S_NAMESPACE", "b")),
                List.of(scope("K8S_NAMESPACE", "b"), scope("AWS_ACCOUNT", "1")));
        assertThat(merged).extracting(DiscoveryFailedScope::getScopeId).containsExactly("a", "b", "1");

        String json = FailedScopes.toJson(merged);
        assertThat(FailedScopes.fromJson(json)).isEqualTo(merged);
        assertThat(FailedScopes.toJson(List.of())).isNull();
        assertThat(FailedScopes.fromJson(null)).isEmpty();
        assertThat(FailedScopes.fromJson("not json")).singleElement()
                .satisfies(s -> assertThat(FailedScopes.covers(s, ACM)).isTrue());
    }

    private static DiscoveryFailedScope scope(String type, String id) {
        return DiscoveryFailedScope.builder().scopeType(type).scopeId(id).errorCode("E").message("m").build();
    }
}

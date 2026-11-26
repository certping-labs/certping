// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.messaging.model.KubernetesDiscoveryData;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KubernetesDiscoveryDataValidatorTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final KubernetesDiscoveryDataValidator validator =
            new KubernetesDiscoveryDataValidator(objectMapper);

    @Test
    void validateAndConvert_acceptsCompleteAgentContract() throws Exception {
        JsonNode payload = objectMapper.readTree(completePayload());

        KubernetesDiscoveryData data = validator.validateAndConvert(payload);

        assertThat(data.clusterName()).isEqualTo("prod-aks");
        assertThat(data.usageComplete()).isTrue();
        assertThat(data.source().kind()).isEqualTo("Secret");
        assertThat(data.usages()).hasSize(1);
        assertThat(data.usages().getFirst().backendServices().getFirst().portNumber()).isEqualTo(443);
        assertThat(data.usages().getFirst().affectedWorkloads().getFirst().containers())
                .containsExactly("payments-api");
        assertThat(data.impact().externallyServed()).isTrue();
        assertThat(data.warnings()).isEmpty();
    }

    @Test
    void validateAndConvert_allowsOptionalUidsAndNullableBackendPortName() throws Exception {
        JsonNode payload = objectMapper.readTree(completePayload());

        KubernetesDiscoveryData data = validator.validateAndConvert(payload);

        assertThat(data.source().uid()).isNull();
        assertThat(data.usages().getFirst().uid()).isNull();
        assertThat(data.usages().getFirst().backendServices().getFirst().portName()).isNull();
    }

    @Test
    void validateAndConvert_rejectsMissingCompletenessFlag() throws Exception {
        JsonNode payload = objectMapper.readTree(completePayload());
        ((tools.jackson.databind.node.ObjectNode) payload).remove("usageComplete");

        assertThatThrownBy(() -> validator.validateAndConvert(payload))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("usageComplete is required");
    }

    @Test
    void validateAndConvert_rejectsMissingUsageCollections() throws Exception {
        JsonNode payload = objectMapper.readTree(completePayload());
        ((tools.jackson.databind.node.ObjectNode) payload.get("usages").get(0))
                .remove("affectedWorkloads");

        assertThatThrownBy(() -> validator.validateAndConvert(payload))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("affectedWorkloads is required");
    }

    private String completePayload() {
        return """
                {
                  "clusterName": "prod-aks",
                  "usageComplete": true,
                  "impactComplete": true,
                  "unreadableResourceTypes": [],
                  "source": {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "namespace": "payments",
                    "name": "payments-tls",
                    "type": "kubernetes.io/tls",
                    "fingerprintSha256": "11:22:33:44"
                  },
                  "usages": [{
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "Gateway",
                    "namespace": "payments",
                    "name": "payments-gateway",
                    "fieldPath": "spec.listeners[0].tls.certificateRefs[0].name",
                    "usageType": "TLS_TERMINATION",
                    "hostnames": ["payments.example.com"],
                    "backendServices": [{
                      "namespace": "payments",
                      "name": "payments-api",
                      "portName": null,
                      "portNumber": 443
                    }],
                    "affectedWorkloads": [{
                      "apiVersion": "apps/v1",
                      "kind": "Deployment",
                      "namespace": "payments",
                      "name": "payments-api",
                      "containers": ["payments-api"],
                      "referencePath": "service selector"
                    }],
                    "confidence": "HIGH"
                  }],
                  "impact": {
                    "externallyServed": true,
                    "directlyMountedByWorkloads": false,
                    "affectedHostnames": ["payments.example.com"],
                    "affectedServices": ["payments/payments-api"],
                    "affectedWorkloads": ["payments/Deployment/payments-api"],
                    "summary": "Expiry can break external TLS for payments.example.com."
                  },
                  "warnings": []
                }
                """;
    }
}

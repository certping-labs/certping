// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KubernetesTraefikServiceIndexTest {

    @Test
    void nativeServicesFor_cyclicTraefikServiceReferences_returnsEmptyWithoutLooping() {
        KubernetesTraefikServiceIndex index = new KubernetesTraefikServiceIndex();
        index.add(traefikService("apps", "first", Map.of(
                "weighted", Map.of("services", List.of(Map.of(
                        "kind", "TraefikService",
                        "name", "second"))))));
        index.add(traefikService("apps", "second", Map.of(
                "weighted", Map.of("services", List.of(Map.of(
                        "kind", "TraefikService",
                        "name", "first"))))));

        assertThat(index.nativeServicesFor("apps", "first")).isEmpty();
    }

    private Map<String, Object> traefikService(String namespace, String name, Map<String, Object> spec) {
        return Map.of(
                "metadata", Map.of("namespace", namespace, "name", name),
                "spec", spec);
    }
}

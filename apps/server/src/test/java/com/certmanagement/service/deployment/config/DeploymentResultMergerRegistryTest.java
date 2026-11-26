// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import com.certmanagement.messaging.model.TargetType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DeploymentResultMergerRegistryTest {

    @Test
    void index_registersByTargetType() {
        DeploymentResultMerger merger = mock(DeploymentResultMerger.class);
        when(merger.supportedTargetTypes()).thenReturn(Set.of(TargetType.AZURE_KV));

        DeploymentResultMergerRegistry registry = new DeploymentResultMergerRegistry(List.of(merger));
        registry.index();

        Optional<DeploymentResultMerger> found = registry.find(TargetType.AZURE_KV);
        assertThat(found).contains(merger);
    }

    @Test
    void index_duplicateTargetType_throws() {
        DeploymentResultMerger first = mock(DeploymentResultMerger.class);
        DeploymentResultMerger second = mock(DeploymentResultMerger.class);
        when(first.supportedTargetTypes()).thenReturn(Set.of(TargetType.AWS_ACM));
        when(second.supportedTargetTypes()).thenReturn(Set.of(TargetType.AWS_ACM));

        DeploymentResultMergerRegistry registry = new DeploymentResultMergerRegistry(List.of(first, second));

        assertThatThrownBy(registry::index)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Multiple DeploymentResultMergers");
    }
}

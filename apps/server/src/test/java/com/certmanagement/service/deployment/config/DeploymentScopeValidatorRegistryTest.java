// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import com.certmanagement.messaging.model.TargetType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DeploymentScopeValidatorRegistryTest {

    @Test
    void index_buildsLookup_findReturnsValidator() {
        DeploymentScopeValidator v = mock(DeploymentScopeValidator.class);
        when(v.supportedTargetTypes()).thenReturn(Set.of(TargetType.AZURE_KV, TargetType.AWS_ACM));

        DeploymentScopeValidatorRegistry registry = new DeploymentScopeValidatorRegistry(List.of(v));
        registry.index();

        assertThat(registry.find(TargetType.AZURE_KV)).containsSame(v);
        assertThat(registry.find(TargetType.AWS_ACM)).containsSame(v);
    }

    @Test
    void find_unregisteredType_returnsEmpty() {
        DeploymentScopeValidatorRegistry registry = new DeploymentScopeValidatorRegistry(List.of());
        registry.index();
        assertThat(registry.find(TargetType.AZURE_KV)).isEmpty();
    }

    @Test
    void index_duplicateValidatorsForSameType_throws() {
        DeploymentScopeValidator v1 = mock(DeploymentScopeValidator.class);
        DeploymentScopeValidator v2 = mock(DeploymentScopeValidator.class);
        when(v1.supportedTargetTypes()).thenReturn(Set.of(TargetType.AZURE_KV));
        when(v2.supportedTargetTypes()).thenReturn(Set.of(TargetType.AZURE_KV));

        DeploymentScopeValidatorRegistry registry = new DeploymentScopeValidatorRegistry(List.of(v1, v2));

        assertThatThrownBy(registry::index)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Multiple DeploymentScopeValidators");
    }

    @Test
    void index_sameValidatorTwice_isIdempotent() {
        DeploymentScopeValidator v = mock(DeploymentScopeValidator.class);
        when(v.supportedTargetTypes()).thenReturn(Set.of(TargetType.AZURE_KV));
        DeploymentScopeValidatorRegistry registry = new DeploymentScopeValidatorRegistry(List.of(v, v));
        registry.index();
        assertThat(registry.find(TargetType.AZURE_KV)).containsSame(v);
    }
}

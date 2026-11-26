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

class DeploymentTargetsValidatorRegistryTest {

    @Test
    void index_registersByTargetType() {
        DeploymentTargetsValidator validator = mock(DeploymentTargetsValidator.class);
        when(validator.supportedTargetTypes()).thenReturn(Set.of(TargetType.GCP_CERT_MANAGER));

        DeploymentTargetsValidatorRegistry registry = new DeploymentTargetsValidatorRegistry(List.of(validator));
        registry.index();

        Optional<DeploymentTargetsValidator> found = registry.find(TargetType.GCP_CERT_MANAGER);
        assertThat(found).contains(validator);
    }

    @Test
    void index_duplicateTargetType_throws() {
        DeploymentTargetsValidator first = mock(DeploymentTargetsValidator.class);
        DeploymentTargetsValidator second = mock(DeploymentTargetsValidator.class);
        when(first.supportedTargetTypes()).thenReturn(Set.of(TargetType.GCP_PROXY_NLB));
        when(second.supportedTargetTypes()).thenReturn(Set.of(TargetType.GCP_PROXY_NLB));

        DeploymentTargetsValidatorRegistry registry = new DeploymentTargetsValidatorRegistry(List.of(first, second));

        assertThatThrownBy(registry::index)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Multiple DeploymentTargetsValidators");
    }
}

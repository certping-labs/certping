// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.domain;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IntegrationTest {

    private Integration newIntegration() {
        return new Integration(7L, IntegrationProvider.SLACK,
                Map.of("webhook_host", "hooks.slack.com"),
                Map.of("webhook_url", "https://hooks.slack.com/x"),
                100L);
    }

    @Test
    void constructor_setsActiveStatusAndCopiesMaps() {
        Integration i = newIntegration();
        assertThat(i.getOrganizationId()).isEqualTo(7L);
        assertThat(i.getProvider()).isEqualTo(IntegrationProvider.SLACK);
        assertThat(i.getStatus()).isEqualTo(IntegrationStatus.ACTIVE);
        assertThat(i.getConfig()).containsEntry("webhook_host", "hooks.slack.com");
        assertThat(i.getSecretRefs()).containsEntry("webhook_url", "https://hooks.slack.com/x");
        assertThat(i.getCreatedBy()).isEqualTo(100L);
        assertThat(i.getUpdatedBy()).isEqualTo(100L);
        assertThat(i.isDeleted()).isFalse();
        assertThat(i.getSecretRef("webhook_url")).isEqualTo("https://hooks.slack.com/x");
        assertThat(i.getSecretRef("missing")).isNull();
    }

    @Test
    void constructor_nullMaps_defaultToEmpty() {
        Integration i = new Integration(1L, IntegrationProvider.TEAMS, null, null, 5L);
        assertThat(i.getConfig()).isEmpty();
        assertThat(i.getSecretRefs()).isEmpty();
        assertThat(i.getSecretRef("any")).isNull();
    }

    @Test
    void lifecycleCallbacks_setTimestamps() {
        Integration i = newIntegration();
        ReflectionTestUtils.invokeMethod(i, "onCreate");
        assertThat(i.getCreatedAt()).isNotNull();
        assertThat(i.getUpdatedAt()).isNotNull();

        java.time.Instant created = i.getUpdatedAt();
        ReflectionTestUtils.invokeMethod(i, "onUpdate");
        assertThat(i.getUpdatedAt()).isAfterOrEqualTo(created);
    }

    @Test
    void replaceConfiguration_updatesAndReactivates() {
        Integration i = newIntegration();
        i.softDelete(9L);
        assertThat(i.isDeleted()).isTrue();
        assertThat(i.getStatus()).isEqualTo(IntegrationStatus.DISABLED);

        i.replaceConfiguration(Map.of("a", "b"), Map.of("c", "d"), 11L);
        assertThat(i.getStatus()).isEqualTo(IntegrationStatus.ACTIVE);
        assertThat(i.getConfig()).containsEntry("a", "b");
        assertThat(i.getSecretRefs()).containsEntry("c", "d");
        assertThat(i.getUpdatedBy()).isEqualTo(11L);
        assertThat(i.isDeleted()).isFalse();
        assertThat(i.getDeletedBy()).isNull();
    }

    @Test
    void softDelete_setsDeletedMetadata() {
        Integration i = newIntegration();
        i.softDelete(42L);
        assertThat(i.getDeletedBy()).isEqualTo(42L);
        assertThat(i.getUpdatedBy()).isEqualTo(42L);
        assertThat(i.getDeletedAt()).isNotNull();
        assertThat(i.isDeleted()).isTrue();
    }
}

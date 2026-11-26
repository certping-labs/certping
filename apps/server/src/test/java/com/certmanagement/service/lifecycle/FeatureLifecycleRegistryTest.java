// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FeatureLifecycleRegistryTest {

    @Test
    void theBlockerTableIsRegisteredAsTheContractDefinesIt() {
        FeatureLifecycleRegistry registry = FeatureLifecycleRegistrationTest.productionRegistry();

        assertThat(registry.registeredFeatureKeys()).containsExactlyInAnyOrder(
                FeatureFlags.CERTIFICATE_DEPLOYMENT,
                FeatureFlags.CERTIFICATE_RENEWAL, FeatureFlags.CERTIFICATE_ISSUANCE, FeatureFlags.CA_LETS_ENCRYPT,
                FeatureFlags.CA_DIGICERT, FeatureFlags.CA_GLOBALSIGN,
                FeatureFlags.CREDENTIALS_MANAGEMENT, FeatureFlags.DISCOVERY,
                FeatureFlags.DNS_CREDENTIALS, FeatureFlags.INTEGRATIONS);
        assertThat(registry.pausable()).extracting(FeatureLifecycle::featureKey).containsExactly(
                FeatureFlags.CERTIFICATE_RENEWAL, FeatureFlags.DISCOVERY);
        assertThat(registry.findPausable(FeatureFlags.DNS_CREDENTIALS)).as("automatic renewal requires it")
                .map(FeatureLifecycle::featureKey).contains(FeatureFlags.CERTIFICATE_RENEWAL);
        assertThat(registry.findPausable(FeatureFlags.CA_LETS_ENCRYPT)).isEmpty();
        assertThat(registry.findPausable(FeatureFlags.INTEGRATIONS)).isEmpty();
        assertThat(registry.find(FeatureFlags.ALERTS)).isEmpty();
        assertThat(registry.find(null)).isEmpty();
    }

    @Test
    void aRequiredFlagWithItsOwnLifecycleIsRefusedAtStartup() {
        CertificateLifecycleRepository certificates = mock(CertificateLifecycleRepository.class);
        FeatureLifecycleConfiguration configuration = new FeatureLifecycleConfiguration();
        HeldRenewalsLifecycle dnsCredentials = new HeldRenewalsLifecycle(FeatureFlags.DNS_CREDENTIALS,
                BlockerKind.AUTO_RENEW_CERTS, "DNS", CertificateLifecycleRepository.AutoRenewScope.everyCa(),
                "FEATURE_HOLD", certificates);

        assertThatThrownBy(() -> new FeatureLifecycleRegistry(List.of(
                configuration.certificateRenewalLifecycle(certificates), dnsCredentials)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(FeatureFlags.DNS_CREDENTIALS);
    }

    @Test
    void aFeatureIsEitherRegisteredOrConsciouslyNothingToClearNeverBoth() {
        FeatureLifecycleRegistry registry = FeatureLifecycleRegistrationTest.productionRegistry();

        assertThat(registry.registeredFeatureKeys()).doesNotContainAnyElementsOf(
                FeatureLifecycleRegistry.NOTHING_TO_CLEAR);
        Set<String> declaredKeys = Arrays.stream(FeatureFlags.class.getDeclaredFields())
                .filter(field -> Modifier.isStatic(field.getModifiers()) && field.getType() == String.class)
                .map(field -> {
                    try {
                        return (String) field.get(null);
                    } catch (IllegalAccessException e) {
                        throw new IllegalStateException(e);
                    }
                })
                .collect(Collectors.toSet());
        assertThat(declaredKeys).containsAll(FeatureLifecycleRegistry.NOTHING_TO_CLEAR)
                .containsAll(registry.registeredFeatureKeys());
    }

    @Test
    void twoLifecyclesForOneFeatureAreAWiringError() {
        FeatureLifecycle first = mock(FeatureLifecycle.class);
        FeatureLifecycle second = mock(FeatureLifecycle.class);
        when(first.featureKey()).thenReturn("X");
        when(second.featureKey()).thenReturn("X");

        assertThatThrownBy(() -> new FeatureLifecycleRegistry(List.of(first, second)))
                .isInstanceOf(IllegalStateException.class);
    }
}

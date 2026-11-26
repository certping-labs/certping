// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.AffectedOrganizations;
import com.certmanagement.repository.lifecycle.ImpactOrganizationsRepository;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.dto.featureflags.FeatureImpactResponse;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.RecordImpact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureImpactServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-06T00:00:00Z");

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private CertificateLifecycleRepository certificates;
    @Mock private PlatformPausableLifecycle discovery;
    @Mock private FeatureLifecycle renewal;
    @Mock private ImpactOrganizationsRepository impactOrganizations;

    /** Real selects (built without a query) as the repositories hand them out. */
    private final AffectedOrganizations scanOrganizations = new CertificateLifecycleRepository(
            org.mockito.Mockito.mock(NamedParameterJdbcTemplate.class))
            .pendingIssuanceOrganizations(ImpactScope.everyOrganization());

    private FeatureImpactService service;

    @BeforeEach
    void setUp() {
        service = new FeatureImpactService(registry, certificates, impactOrganizations,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void aPausableFeatureNotifiesAdmins() {
        when(registry.find("DISCOVERY")).thenReturn(Optional.of(discovery));
        when(registry.findPausable("DISCOVERY")).thenReturn(Optional.of(discovery));
        when(discovery.impact(ImpactScope.everyOrganization())).thenReturn(List.of(new ImpactCount(
                BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 1840, 212)));
        when(discovery.affectedOrganizations(ImpactScope.everyOrganization())).thenReturn(List.of(scanOrganizations));
        when(impactOrganizations.countDistinct(List.of(scanOrganizations))).thenReturn(212L);

        FeatureImpactResponse impact = service.impact("DISCOVERY", ImpactScope.everyOrganization());

        assertThat(impact.organizationsAffected()).isEqualTo(212);
        assertThat(impact.items()).containsExactly(new FeatureImpactResponse.Item(BlockerKind.RUNNING_DISCOVERY_SCANS,
                "Running discovery scans", 1840));
        assertThat(impact.notifiesAdmins()).isTrue();
        assertThat(impact.warnings()).isEmpty();
        verify(certificates, never()).expiringCertificates(any(), any(), any(), anyBoolean());
    }

    @Test
    void renewalWarnsAboutCertificatesExpiringWithinThirtyDays() {
        when(registry.find("CERTIFICATE_RENEWAL")).thenReturn(Optional.of(renewal));
        when(renewal.impact(ImpactScope.organization(5L))).thenReturn(List.of(new ImpactCount(BlockerKind.AUTO_RENEW_CERTS,
                "Certificates set to renew automatically", 0, 0)));
        when(certificates.expiringCertificates(ImpactScope.organization(5L), OffsetDateTime.parse("2026-11-05T00:00Z"), null, false))
                .thenReturn(new RecordImpact(412, 37));

        FeatureImpactResponse impact = service.impact("CERTIFICATE_RENEWAL", ImpactScope.organization(5L));

        assertThat(impact.items()).isEmpty();
        assertThat(impact.organizationsAffected()).isZero();
        assertThat(impact.notifiesAdmins()).isFalse();
        verify(impactOrganizations, never()).countDistinct(any());
        assertThat(impact.warnings())
                .containsExactly("412 certificates across 37 organizations expire in the next 30 days");
    }

    @Test
    void aCaFlagWarnsOnlyAboutItsOwnCertificatesAndDeploymentOnlyAboutDeployedOnes() {
        when(certificates.expiringCertificates(any(), any(), eq("DIGICERT"), eq(false)))
                .thenReturn(new RecordImpact(1, 1));
        when(certificates.expiringCertificates(any(), any(), eq(null), eq(true))).thenReturn(new RecordImpact(0, 0));
        when(certificates.expiringCertificates(any(), any(), eq(null), eq(false))).thenReturn(new RecordImpact(0, 0));

        assertThat(service.impact("DIGICERT", ImpactScope.orgType("B2B")).warnings())
                .containsExactly("1 certificate across 1 organization expires in the next 30 days");
        assertThat(service.impact("CERTIFICATE_DEPLOYMENT", ImpactScope.everyOrganization()).warnings()).isEmpty();
        assertThat(service.impact("AUTO_RENEWAL", ImpactScope.everyOrganization()).items()).isEmpty();
    }

    @Test
    void organizationsAffectedIsTheDistinctCountAcrossEveryKindNotTheLargestKind() {
        AffectedOrganizations issuing = new CertificateLifecycleRepository(
                org.mockito.Mockito.mock(NamedParameterJdbcTemplate.class))
                .pendingIssuanceOrganizations(ImpactScope.everyOrganization());
        when(registry.find("DISCOVERY")).thenReturn(Optional.of(discovery));
        when(discovery.impact(ImpactScope.everyOrganization())).thenReturn(List.of(
                new ImpactCount(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 10, 4),
                new ImpactCount(BlockerKind.PENDING_ISSUANCES, "Certificate issuances in progress", 3, 3)));
        when(discovery.affectedOrganizations(ImpactScope.everyOrganization()))
                .thenReturn(List.of(scanOrganizations, issuing));
        when(impactOrganizations.countDistinct(List.of(scanOrganizations, issuing))).thenReturn(6L);

        assertThat(service.impact("DISCOVERY", ImpactScope.everyOrganization())
                .organizationsAffected()).isEqualTo(6);
    }



    @Test
    void aFeatureWithNothingToClearHasNoImpact() {
        FeatureImpactResponse impact = service.impact("ALERTS", ImpactScope.everyOrganization());

        assertThat(impact.items()).isEmpty();
        assertThat(impact.warnings()).isEmpty();
    }
}

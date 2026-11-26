// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.repository.lifecycle.AccessLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewScope;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewCount;
import com.certmanagement.repository.lifecycle.DiscoveryLifecycleRepository;
import com.certmanagement.repository.lifecycle.RecordImpact;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The non-pausable lifecycles of the blocker table, plus discovery's cancel. */
@ExtendWith(MockitoExtension.class)
class CertificateAndAccessLifecyclesTest {

    private static final long ORG = 7L;

    @Mock private CertificateLifecycleRepository certificates;
    @Mock private AccessLifecycleRepository access;
    @Mock private DiscoveryLifecycleRepository scans;

    private final FeatureLifecycleConfiguration configuration = new FeatureLifecycleConfiguration();
    private CertificateDeploymentLifecycle deployment;
    private DiscoveryLifecycle discovery;

    @BeforeEach
    void setUp() {
        deployment = new CertificateDeploymentLifecycle(certificates);
        discovery = new DiscoveryLifecycle(scans);
    }

    @Test
    void deploymentTargetsBlockAndClearTargetsEmptiesThem() {
        when(certificates.countDeploymentTargets(ORG)).thenReturn(4L);
        when(certificates.clearDeploymentTargets(ORG)).thenReturn(4L);

        assertThat(deployment.blockers(ORG)).containsExactly(new Blocker(BlockerKind.DEPLOYMENT_TARGETS,
                "Deployment targets", 4, "/cert-manager/deployments", List.of(ClearAction.CLEAR_TARGETS)));
        assertThat(deployment.clear(ORG, BlockerKind.DEPLOYMENT_TARGETS, ClearAction.CLEAR_TARGETS)).isEqualTo(4);
        assertThatThrownBy(() -> deployment.clear(ORG, BlockerKind.DEPLOYMENT_TARGETS, ClearAction.DELETE_ALL))
                .isInstanceOf(UnsupportedClearException.class);
    }

    @Test
    void renewalLabelNamesTheNearestExpiryAndDisablingCoversEveryCa() {
        HeldRenewalsLifecycle renewal = configuration.certificateRenewalLifecycle(certificates);
        when(certificates.countAutoRenew(ORG, AutoRenewScope.everyCa()))
                .thenReturn(new AutoRenewCount(12, OffsetDateTime.parse("2026-11-02T10:00:00Z")));
        when(certificates.disableAutoRenew(ORG, AutoRenewScope.everyCa())).thenReturn(12);

        assertThat(renewal.blockers(ORG)).singleElement().satisfies(blocker -> {
            assertThat(blocker.kind()).isEqualTo(BlockerKind.AUTO_RENEW_CERTS);
            assertThat(blocker.label()).isEqualTo("Certificates set to renew automatically (next expiry 2 Nov 2026)");
            assertThat(blocker.actions()).containsExactly(ClearAction.DISABLE_AUTO_RENEW);
        });
        assertThat(renewal.clear(ORG, BlockerKind.AUTO_RENEW_CERTS, ClearAction.DISABLE_AUTO_RENEW)).isEqualTo(12);
    }

    @Test
    void eachCaFlagCountsAndDisablesOnlyItsOwnCertificates() {
        AutoRenewLifecycle letsEncrypt = configuration.letsEncryptLifecycle(certificates);
        AutoRenewLifecycle digicert = configuration.digicertLifecycle(certificates);
        when(certificates.countAutoRenew(ORG, AutoRenewScope.onCa("LETS_ENCRYPT"))).thenReturn(new AutoRenewCount(2, null));
        when(certificates.countAutoRenew(ORG, AutoRenewScope.onCa("DIGICERT"))).thenReturn(new AutoRenewCount(0, null));

        assertThat(letsEncrypt.featureKey()).isEqualTo("LETS_ENCRYPT");
        assertThat(letsEncrypt.blockers(ORG)).extracting(Blocker::kind, Blocker::label, Blocker::count)
                .containsExactly(org.assertj.core.groups.Tuple.tuple(BlockerKind.AUTO_RENEW_CERTS_ON_CA,
                        "Let's Encrypt certificates set to renew automatically", 2L));
        assertThat(digicert.blockers(ORG)).isEmpty();

        letsEncrypt.clear(ORG, BlockerKind.AUTO_RENEW_CERTS_ON_CA, ClearAction.DISABLE_AUTO_RENEW);
        verify(certificates).disableAutoRenew(ORG, AutoRenewScope.onCa("LETS_ENCRYPT"));
        assertThat(configuration.globalSignLifecycle(certificates).featureKey()).isEqualTo("GLOBALSIGN");
    }

    @Test
    void linkOnlyKindsBlockWithoutActionsAndRefuseEveryClear() {
        LinkOnlyLifecycle issuance = configuration.certificateIssuanceLifecycle(certificates);
        LinkOnlyLifecycle integrations = configuration.integrationsLifecycle(access);
        LinkOnlyLifecycle credentials = configuration.credentialsLifecycle(access);
        when(certificates.countPendingIssuances(ORG)).thenReturn(1L);
        when(access.countActiveIntegrations(ORG)).thenReturn(2L);
        when(access.countActiveCredentials(ORG)).thenReturn(0L);

        assertThat(issuance.blockers(ORG)).containsExactly(new Blocker(BlockerKind.PENDING_ISSUANCES,
                "Certificate issuances in progress", 1, "/cert-manager/manage", List.of()));
        assertThat(integrations.blockers(ORG)).containsExactly(new Blocker(BlockerKind.ACTIVE_INTEGRATIONS,
                "Active integrations", 2, "/integrations/apps", List.of()));
        assertThat(credentials.blockers(ORG)).isEmpty();
        for (ClearAction action : ClearAction.values()) {
            assertThatThrownBy(() -> integrations.clear(ORG, BlockerKind.ACTIVE_INTEGRATIONS, action))
                    .isInstanceOf(UnsupportedClearException.class);
        }
        assertThat(integrations.supportedActions(BlockerKind.ACTIVE_INTEGRATIONS)).isEmpty();
    }

    @Test
    void linkOnlyImpactAggregates() {
        when(access.activeCredentialsImpact(ImpactScope.orgType("B2B"))).thenReturn(new RecordImpact(30, 9));

        assertThat(configuration.credentialsLifecycle(access).impact(ImpactScope.orgType("B2B"))).containsExactly(
                new ImpactCount(BlockerKind.CREDENTIALS_IN_USE, "Active credentials", 30, 9));
    }

    @Test
    void runningScansBlockAndCancelAllCancelsThem() {
        when(scans.countRunning(ORG)).thenReturn(2L);
        when(scans.cancelRunning(ORG, DiscoveryLifecycle.CANCELLED_MESSAGE)).thenReturn(2);

        assertThat(discovery.blockers(ORG)).containsExactly(new Blocker(BlockerKind.RUNNING_DISCOVERY_SCANS,
                "Running discovery scans", 2, "/cert-manager/discovery", List.of(ClearAction.CANCEL_ALL)));
        assertThat(discovery.clear(ORG, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.CANCEL_ALL)).isEqualTo(2);
    }

    @Test
    void thePlatformCancelsRunningScansAndNeverRestartsThem() {
        when(scans.cancelRunning(ORG, DiscoveryLifecycle.CANCELLED_MESSAGE)).thenReturn(3, 0);

        assertThat(discovery.platformPause(ORG)).containsExactly(
                new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, "Discovery scans stopped", 3));
        assertThat(discovery.platformPause(ORG)).isEmpty();
        assertThat(discovery.platformResume(ORG)).isEmpty();
        assertThatThrownBy(() -> discovery.clear(ORG, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.PAUSE_ALL))
                .isInstanceOf(UnsupportedClearException.class);
        verify(scans, never()).countRunning(anyLong());
        verify(scans, org.mockito.Mockito.times(2)).cancelRunning(anyLong(), any());
    }
}

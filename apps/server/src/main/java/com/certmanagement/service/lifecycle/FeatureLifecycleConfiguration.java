// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.RenewalStatus;
import com.certmanagement.repository.lifecycle.AccessLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

import static com.certmanagement.service.lifecycle.ClearAction.DELETE_ALL;
import static com.certmanagement.service.lifecycle.ClearAction.PAUSE_ALL;

/**
 * The lifecycles that share an implementation and differ only in data; {@link DiscoveryLifecycle} and {@link CertificateDeploymentLifecycle} are components.
 */
@Configuration
public class FeatureLifecycleConfiguration {

    @Bean
    HeldRenewalsLifecycle certificateRenewalLifecycle(CertificateLifecycleRepository certificates) {
        return new HeldRenewalsLifecycle(FeatureFlags.CERTIFICATE_RENEWAL, BlockerKind.AUTO_RENEW_CERTS,
                "Certificates set to renew automatically", AutoRenewScope.everyCa(),
                RenewalStatus.FEATURE_HOLD.name(), certificates);
    }

    @Bean
    AutoRenewLifecycle letsEncryptLifecycle(CertificateLifecycleRepository certificates) {
        return caLifecycle(FeatureFlags.CA_LETS_ENCRYPT, CaProvider.LETS_ENCRYPT, "Let's Encrypt", certificates);
    }

    @Bean
    AutoRenewLifecycle digicertLifecycle(CertificateLifecycleRepository certificates) {
        return caLifecycle(FeatureFlags.CA_DIGICERT, CaProvider.DIGICERT, "DigiCert", certificates);
    }

    @Bean
    AutoRenewLifecycle globalSignLifecycle(CertificateLifecycleRepository certificates) {
        return caLifecycle(FeatureFlags.CA_GLOBALSIGN, CaProvider.GLOBALSIGN, "GlobalSign", certificates);
    }

    @Bean
    LinkOnlyLifecycle certificateIssuanceLifecycle(CertificateLifecycleRepository certificates) {
        return new LinkOnlyLifecycle(FeatureFlags.CERTIFICATE_ISSUANCE, BlockerKind.PENDING_ISSUANCES,
                "Certificate issuances in progress", "/cert-manager/manage",
                certificates::countPendingIssuances, certificates::pendingIssuancesImpact,
                certificates::pendingIssuanceOrganizations);
    }

    /**
     * Link-only: the platform does not deactivate integrations on a switch-off, because nothing could
     * tell which ones to turn back on; delivery is skipped while the feature is off instead
     * ({@code IntegrationDeliveryGate}).
     */
    @Bean
    LinkOnlyLifecycle integrationsLifecycle(AccessLifecycleRepository access) {
        return new LinkOnlyLifecycle(FeatureFlags.INTEGRATIONS, BlockerKind.ACTIVE_INTEGRATIONS,
                "Active integrations", "/integrations/apps",
                access::countActiveIntegrations, access::activeIntegrationsImpact,
                access::activeIntegrationOrganizations);
    }

    @Bean
    LinkOnlyLifecycle credentialsLifecycle(AccessLifecycleRepository access) {
        return new LinkOnlyLifecycle(FeatureFlags.CREDENTIALS_MANAGEMENT, BlockerKind.CREDENTIALS_IN_USE,
                "Active credentials", "/integrations/connections",
                access::countActiveCredentials, access::activeCredentialsImpact,
                access::activeCredentialOrganizations);
    }

    private static AutoRenewLifecycle caLifecycle(String featureKey, CaProvider caProvider, String caName,
                                                  CertificateLifecycleRepository certificates) {
        return new AutoRenewLifecycle(featureKey, BlockerKind.AUTO_RENEW_CERTS_ON_CA,
                caName + " certificates set to renew automatically", AutoRenewScope.onCa(caProvider.name()),
                certificates);
    }
}

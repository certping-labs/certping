// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.enums.KeyCustody;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Set;

/**
 * Decides from a certificate row alone whether its material can be exported. Never calls the
 * secret store or the database, so it is safe to run for every row of a list page.
 *
 * <p><b>Platform stored</b> means the agent wrote the certificate into the agent secret store this
 * server is configured for: the store is configured and the handle points into that store at
 * the secret named after this certificate. A handle into any other vault (an agent configured to
 * write to a vault of its own) is not platform stored, because a same-named read here would miss or
 * mis-resolve it.
 */
@Component
public class CertExportEligibilityPolicy {

    /** ACTIVE, and RENEWING: the cert stays live and its material stays in place until the renewal lands. */
    private static final Set<String> EXPORTABLE_STATUSES =
            Set.of(CertificateStatus.ACTIVE.name(), CertificateStatus.RENEWING.name());

    private final ObjectProvider<AgentSecretStore> secretStoreProvider;
    private final Clock clock;

    public CertExportEligibilityPolicy(ObjectProvider<AgentSecretStore> secretStoreProvider, Clock clock) {
        this.secretStoreProvider = secretStoreProvider;
        this.clock = clock;
    }

    /**
     * Evaluates {@code cert} for a certificate response. {@code downloadEnabled} is the
     * {@code CERTIFICATE_DOWNLOAD} flag for the org the response serves, resolved once per request
     * by the caller; when it is off nothing else is checked.
     */
    public CertExportEligibility evaluate(CertificateEntity cert, boolean downloadEnabled) {
        return downloadEnabled ? evaluate(cert)
                : CertExportEligibility.unavailable(CertExportUnavailableReason.FEATURE_DISABLED);
    }

    /** Evaluates {@code cert}; checks run from the most to the least fundamental reason. */
    public CertExportEligibility evaluate(CertificateEntity cert) {
        if (isExpired(cert)) {
            return CertExportEligibility.unavailable(CertExportUnavailableReason.EXPIRED);
        }
        if (!EXPORTABLE_STATUSES.contains(cert.getStatus())) {
            return CertExportEligibility.unavailable(CertExportUnavailableReason.NOT_ACTIVE);
        }
        if (isBlank(cert.getCertSecretHandle()) || isBlank(cert.getFingerprintSha256())) {
            return CertExportEligibility.unavailable(CertExportUnavailableReason.NO_MATERIAL);
        }
        if (!isPlatformStored(cert)) {
            return CertExportEligibility.unavailable(CertExportUnavailableReason.NOT_PLATFORM_STORED);
        }
        return cert.getKeyCustody() == KeyCustody.CUSTOMER_HELD
                ? CertExportEligibility.exportableWithoutPrivateKey()
                : CertExportEligibility.exportable();
    }

    private boolean isExpired(CertificateEntity cert) {
        if (CertificateStatus.EXPIRED.name().equals(cert.getStatus())) {
            return true;
        }
        OffsetDateTime validTo = cert.getValidTo();
        return validTo != null && !validTo.toInstant().isAfter(clock.instant());
    }

    private boolean isPlatformStored(CertificateEntity cert) {
        AgentSecretStore store = secretStoreProvider.getIfAvailable();
        return store != null && store.isReady()
                && store.isAgentCertificateHandle(cert.getCertSecretHandle(), cert.getCertificateXref());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}

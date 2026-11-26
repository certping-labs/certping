// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.repository.lifecycle.AffectedOrganizations;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewCount;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository.AutoRenewScope;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.repository.lifecycle.RecordImpact;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * A feature blocked while certificates are set to renew automatically: {@code CERTIFICATE_RENEWAL}
 * for every CA ({@link BlockerKind#AUTO_RENEW_CERTS}), or one CA flag for that CA's certificates
 * ({@link BlockerKind#AUTO_RENEW_CERTS_ON_CA}). Cleared by turning automatic renewal off; the label
 * names the nearest expiry so the admin sees what is at stake. Instances are built in
 * {@link FeatureLifecycleConfiguration}.
 */
public class AutoRenewLifecycle implements FeatureLifecycle {

    private static final String HREF = "/cert-manager/manage";
    private static final DateTimeFormatter EXPIRY_FORMAT = DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH);

    private final String featureKey;
    protected final BlockerKind kind;
    protected final String label;
    protected final AutoRenewScope renewals;
    protected final CertificateLifecycleRepository certificates;

    /**
     * @param renewals the renewal schedules the feature covers
     */
    public AutoRenewLifecycle(String featureKey, BlockerKind kind, String label, AutoRenewScope renewals,
                              CertificateLifecycleRepository certificates) {
        this.featureKey = featureKey;
        this.kind = kind;
        this.label = label;
        this.renewals = renewals;
        this.certificates = certificates;
    }

    @Override
    public String featureKey() {
        return featureKey;
    }

    @Override
    public List<BlockerKind> kinds() {
        return List.of(kind);
    }

    @Override
    public Set<ClearAction> supportedActions(BlockerKind blockerKind) {
        return blockerKind == kind ? Set.of(ClearAction.DISABLE_AUTO_RENEW) : Set.of();
    }

    @Override
    public List<Blocker> blockers(long organizationId) {
        AutoRenewCount autoRenew = certificates.countAutoRenew(organizationId, renewals);
        if (autoRenew.records() == 0) {
            return List.of();
        }
        String withExpiry = autoRenew.nearestExpiry() == null ? label
                : label + " (next expiry " + EXPIRY_FORMAT.format(autoRenew.nearestExpiry()) + ")";
        return List.of(new Blocker(kind, withExpiry, autoRenew.records(), HREF,
                List.of(ClearAction.DISABLE_AUTO_RENEW)));
    }

    @Override
    public int clear(long organizationId, BlockerKind blockerKind, ClearAction action) {
        if (!supportedActions(blockerKind).contains(action)) {
            throw new UnsupportedClearException(featureKey, blockerKind, action);
        }
        return certificates.disableAutoRenew(organizationId, renewals);
    }

    @Override
    public List<ImpactCount> impact(ImpactScope scope) {
        RecordImpact impact = certificates.autoRenewImpact(scope, renewals);
        return List.of(new ImpactCount(kind, label, impact.records(), impact.organizations()));
    }

    @Override
    public List<AffectedOrganizations> affectedOrganizations(ImpactScope scope) {
        return List.of(certificates.autoRenewOrganizations(scope, renewals));
    }
}

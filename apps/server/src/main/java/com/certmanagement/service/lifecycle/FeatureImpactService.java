// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.featureflags.FeatureImpactResponse;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.ImpactOrganizationsRepository;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.repository.lifecycle.RecordImpact;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The super admin's preview of switching a feature off: affected records per kind, the distinct
 * organizations holding them, whether admins are emailed, and the risks the counts do not show
 * (certificate expiries). Aggregate queries
 * only (COUNT / COUNT DISTINCT per kind, one UNION for the organizations), whatever the number of
 * organizations.
 */
@Service
@RequiredArgsConstructor
public class FeatureImpactService {

    static final Duration EXPIRY_WARNING_WINDOW = Duration.ofDays(30);

    /** Features whose switch-off leaves certificates expiring without a renewal or a deployment. */
    private static final Map<String, CaProvider> CA_FLAGS = Map.of(
            FeatureFlags.CA_LETS_ENCRYPT, CaProvider.LETS_ENCRYPT,
            FeatureFlags.CA_DIGICERT, CaProvider.DIGICERT,
            FeatureFlags.CA_GLOBALSIGN, CaProvider.GLOBALSIGN);

    private final FeatureLifecycleRegistry registry;
    private final CertificateLifecycleRepository certificates;
    private final ImpactOrganizationsRepository impactOrganizations;
    private final Clock clock;

    /**
     * @param scope every organization, one organization, or one organization type
     */
    @Transactional(readOnly = true)
    public FeatureImpactResponse impact(String featureKey, ImpactScope scope) {
        Optional<FeatureLifecycle> lifecycle = registry.find(featureKey);
        List<ImpactCount> counts = lifecycle.map(found -> found.impact(scope)).orElse(List.of()).stream()
                .filter(count -> count.count() > 0)
                .toList();
        long organizations = counts.isEmpty() ? 0
                : impactOrganizations.countDistinct(lifecycle.orElseThrow().affectedOrganizations(scope));
        return new FeatureImpactResponse(featureKey, organizations,
                counts.stream().map(count -> new FeatureImpactResponse.Item(count.kind(), count.label(),
                        count.count())).toList(),
                organizations > 0 && registry.findPausable(featureKey).isPresent(),
                warnings(featureKey, scope));
    }

    private List<String> warnings(String featureKey, ImpactScope scope) {
        return certificateExpiryWarning(featureKey, scope).map(List::of).orElse(List.of());
    }

    private Optional<String> certificateExpiryWarning(String featureKey, ImpactScope scope) {
        String pausedFeature = registry.find(featureKey).map(FeatureLifecycle::featureKey).orElse(featureKey);
        boolean renewal = FeatureFlags.CERTIFICATE_RENEWAL.equals(pausedFeature)
                || FeatureFlags.AUTO_RENEWAL.equals(featureKey);
        boolean deployment = FeatureFlags.CERTIFICATE_DEPLOYMENT.equals(featureKey);
        CaProvider caProvider = CA_FLAGS.get(featureKey);
        if (!renewal && !deployment && caProvider == null) {
            return Optional.empty();
        }
        OffsetDateTime until = OffsetDateTime.now(clock).plus(EXPIRY_WARNING_WINDOW);
        RecordImpact expiring = certificates.expiringCertificates(scope, until,
                caProvider == null ? null : caProvider.name(), deployment);
        return expiring.records() > 0 ? Optional.of(expiringSentence(expiring)) : Optional.empty();
    }

    static String expiringSentence(RecordImpact expiring) {
        return expiring.records() + (expiring.records() == 1 ? " certificate" : " certificates")
                + " across " + expiring.organizations()
                + (expiring.organizations() == 1 ? " organization" : " organizations")
                + (expiring.records() == 1 ? " expires" : " expire") + " in the next "
                + EXPIRY_WARNING_WINDOW.toDays() + " days";
    }
}

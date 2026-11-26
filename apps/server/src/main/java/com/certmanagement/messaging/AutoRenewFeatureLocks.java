// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The (organization, feature) locks an issuance or renewal success holds for its transaction:
 * {@code CERTIFICATE_RENEWAL} and the certificate's CA flag. Holding them makes the success and an
 * org admin's DISABLE_AUTO_RENEW clear plus switch-off serialize, so a success never lets a renewal
 * run after the org admin found nothing renewing.
 *
 * <p>One instance per transaction: it remembers what it holds so a second request for the same lock
 * is free. Locks are taken in sorted key order, the order every other lock holder uses.
 */
@Slf4j
final class AutoRenewFeatureLocks {

    private final FeatureLifecycleLock lock;
    private final Set<String> held = new HashSet<>();

    AutoRenewFeatureLocks(FeatureLifecycleLock lock) {
        this.lock = lock;
    }

    /**
     * The features whose locks a success needs: renewal plus the CA's flag, or every CA flag when the
     * response does not name its CA (so the lock can still come before any read).
     */
    static List<String> featureKeysFor(CaProvider caProvider) {
        Stream<CaProvider> cas = caProvider != null ? Stream.of(caProvider) : Arrays.stream(CaProvider.values());
        return Stream.concat(Stream.of(FeatureFlags.CERTIFICATE_RENEWAL), cas.map(CertIssuanceService::toCaFeatureKey))
                .distinct()
                .sorted()
                .toList();
    }

    /** Takes, in sorted order, every lock of {@code featureKeys} for the organization not yet held. */
    void acquire(long organizationId, List<String> featureKeys) {
        featureKeys.stream().distinct().sorted()
                .filter(featureKey -> held.add(organizationId + ":" + featureKey))
                .forEach(featureKey -> lock.lock(organizationId, featureKey));
    }

    /**
     * Makes sure the certificate's own locks are held. Only takes anything when the message named no
     * organization, or a CA other than the certificate's; the extra lock then comes after the others
     * (Postgres's deadlock detection is the backstop for that out-of-order case).
     */
    void ensureHeld(long organizationId, CaProvider caProvider) {
        List<String> missing = featureKeysFor(caProvider).stream()
                .filter(featureKey -> !held.contains(organizationId + ":" + featureKey))
                .toList();
        if (!missing.isEmpty() && !held.isEmpty()) {
            log.warn("Success for org={} needed feature locks {} beyond those taken first", organizationId, missing);
        }
        acquire(organizationId, missing);
    }
}

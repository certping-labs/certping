// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.stream.Stream;

/**
 * The clear-first guard of the certificate create paths (issuance, conversion to automated): they
 * take the (organization, feature) locks of everything they put in use, in the sorted order every
 * lock holder uses (so they never deadlock with the issuance/renewal success handlers), then re-read
 * the flags past the cache. An org admin's switch-off that committed while they waited is seen.
 */
@Component
@RequiredArgsConstructor
class CertificateFeatureLocks {

    private final FeatureLifecycleLock lock;
    private final FeatureFlagResolver resolver;

    /**
     * Locks {@code required} and {@code lockedOnly} for the organization, then requires every
     * {@code required} feature to be on. {@code lockedOnly} features are serialized with but not
     * required (the caller copes with them being off).
     *
     * @param deploymentOffMessage the 423 message when {@code CERTIFICATE_DEPLOYMENT} is required and off
     * @throws FeatureDisabledException (423) when a required feature is off
     */
    @Transactional(propagation = Propagation.MANDATORY)
    void lockAndRequire(long organizationId, Collection<String> required, Collection<String> lockedOnly,
                        String deploymentOffMessage) {
        Stream.concat(required.stream(), lockedOnly.stream())
                .distinct()
                .sorted()
                .forEach(featureKey -> lock.lock(organizationId, featureKey));
        for (String featureKey : required) {
            if (!resolver.resolveUncached(featureKey, organizationId)) {
                throw FeatureFlags.CERTIFICATE_DEPLOYMENT.equals(featureKey)
                        ? new FeatureDisabledException(featureKey, "FEATURE_DISABLED", deploymentOffMessage)
                        : new FeatureDisabledException(featureKey);
            }
        }
    }
}

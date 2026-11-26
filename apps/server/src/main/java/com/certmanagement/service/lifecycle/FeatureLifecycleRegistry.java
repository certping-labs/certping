// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Every {@link FeatureLifecycle}, by feature key. A feature without one has no blockers and nothing
 * for the platform to pause. A flag that another feature's automatic work requires
 * ({@link FeatureFlags#AUTOMATIC_WORK_REQUIRES}) maps to that feature's lifecycle: switching it off
 * pauses that work, with the same blockers, forced transitions and emails.
 *
 * <p>{@link #NOTHING_TO_CLEAR} names the ORG-scope features that consciously have no lifecycle;
 * {@code FeatureLifecycleRegistrationTest} fails when an ORG-scope flag is in neither place, so a new
 * organization-controllable feature cannot skip deciding what switching it off must clear.
 */
@Component
public class FeatureLifecycleRegistry {

    /**
     * ORG-scope features whose switch-off leaves nothing running: their jobs stop through
     * {@code JobPolicy} and their data simply stays.
     */
    public static final Set<String> NOTHING_TO_CLEAR = Set.of(
            // Manual issuance waits on the customer's DNS records; nothing runs on its own.
            FeatureFlags.CERTIFICATE_MANUAL_ISSUANCE,
            // Revocation is a one-off action, never a standing record.
            FeatureFlags.CERTIFICATE_REVOCATION,
            // Alert records are history; expiry alerts are a CUSTOMER_PROTECTION job.
            FeatureFlags.ALERTS,
            // The dashboard reads agent heartbeats; agents keep running regardless.
            FeatureFlags.AGENT_HEALTH_MONITORING,
            // IoT sync, digest and fleet-health jobs are FEATURE_WORK and stop; devices are kept.
            FeatureFlags.IOT_DEVICE_MANAGEMENT,
            FeatureFlags.IOT_PROVIDER_INTUNE,
            FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT,
            FeatureFlags.CA_EJBCA,
            FeatureFlags.CA_SMALLSTEP,
            // A report computed on request.
            FeatureFlags.PQC_READINESS,
            // A download on request; nothing is stored or scheduled per organization.
            FeatureFlags.CERTIFICATE_DOWNLOAD,
            // Only hides the feature flags page; every flag keeps its state.
            FeatureFlags.FEATURE_FLAGS_PAGE,
            // Off sends every notification again; the saved choices are kept and ignored.
            FeatureFlags.NOTIFICATION_PREFERENCES);

    private final Map<String, FeatureLifecycle> byFeatureKey;

    public FeatureLifecycleRegistry(List<FeatureLifecycle> lifecycles) {
        Map<String, FeatureLifecycle> own = lifecycles.stream()
                .collect(Collectors.toMap(FeatureLifecycle::featureKey, Function.identity(),
                        (first, second) -> {
                            throw new IllegalStateException("Two lifecycles for feature " + first.featureKey());
                        }));
        Map<String, FeatureLifecycle> all = new HashMap<>(own);
        FeatureFlags.AUTOMATIC_WORK_REQUIRES.forEach((featureKey, requiredKey) -> {
            FeatureLifecycle requiring = own.get(featureKey);
            if (requiring == null) {
                return;
            }
            if (own.containsKey(requiredKey)) {
                throw new IllegalStateException("Feature " + requiredKey + " has its own lifecycle and is required by "
                        + featureKey + "'s; one flag change would pause two lifecycles");
            }
            all.put(requiredKey, requiring);
        });
        this.byFeatureKey = Map.copyOf(all);
    }

    /**
     * The lifecycle switching {@code featureKey} off pauses: its own, or that of the feature whose automatic
     * work requires it. Empty when the feature has nothing to clear.
     */
    public Optional<FeatureLifecycle> find(String featureKey) {
        return Optional.ofNullable(featureKey).map(byFeatureKey::get);
    }

    /** The lifecycle of {@code featureKey} when the platform pauses its records. */
    public Optional<PlatformPausableLifecycle> findPausable(String featureKey) {
        return find(featureKey)
                .filter(PlatformPausableLifecycle.class::isInstance)
                .map(PlatformPausableLifecycle.class::cast);
    }

    /** Every lifecycle whose records the platform pauses. */
    public List<PlatformPausableLifecycle> pausable() {
        return byFeatureKey.values().stream()
                .distinct()
                .filter(PlatformPausableLifecycle.class::isInstance)
                .map(PlatformPausableLifecycle.class::cast)
                .sorted((a, b) -> a.featureKey().compareTo(b.featureKey()))
                .toList();
    }

    public Collection<String> registeredFeatureKeys() {
        return byFeatureKey.keySet();
    }
}

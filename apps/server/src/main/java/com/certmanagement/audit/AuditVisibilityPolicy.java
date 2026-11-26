// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.service.FeatureFlagService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * What a reader of the customer trail sees of features that are off.
 *
 * <ul>
 *   <li>Recording never consults feature flags: everything that happened is written.</li>
 *   <li>The filter options (categories, actions, resource types) of a feature that is off for the
 *       organization are hidden: nothing new can happen there, and an option for it is noise.</li>
 *   <li>The events of such a feature stay in the list (and the export), marked {@code featureOff}: the log
 *       records what happened, and admins investigate exactly around a switch-off. No vendor surveyed
 *       (GitHub, Slack, Atlassian) hides past events because a feature was turned off.</li>
 *   <li>Super admins see every option, each marked whether it is enabled for the organization they read.</li>
 *   <li>Sensitive reads ({@link AuditCategory#ACCESS}) are not options of the list: the default list leaves
 *       them out, and they are read in the Access view (or with {@code category=ACCESS}).</li>
 * </ul>
 *
 * The rule lives here only. To hide the events too, make
 * {@link Viewer#hiddenFeatureKeys()} return {@link Viewer#disabledFeatureKeys()} for non-super-admins:
 * the store then adds {@code AND (feature_key IS NULL OR feature_key NOT IN (...))}.
 */
@Component
public class AuditVisibilityPolicy {

    private final FeatureFlagService featureFlags;

    public AuditVisibilityPolicy(FeatureFlagService featureFlags) {
        this.featureFlags = featureFlags;
    }

    /**
     * The policy for one reader: a super admin or not, reading {@code organizationId}'s trail ({@code null}:
     * a super admin reading every organization). Feature states are looked up once per organization.
     */
    public Viewer viewer(boolean superAdmin, Long organizationId) {
        Map<Long, Set<String>> byOrganization = new HashMap<>();
        Function<Long, Set<String>> disabled = org -> org == null ? Set.of()
                : byOrganization.computeIfAbsent(org, featureFlags::disabledFeatureKeys);
        return new Viewer(superAdmin, organizationId, disabled, featureFlags::disabledFeatureKeysFor);
    }

    /** The categories the reader may filter by, in catalog order; see the class comment. */
    public List<AuditCategoryOption> categories(Viewer viewer) {
        Map<AuditCategory, List<AuditEventType>> byCategory = customerEvents().stream()
                .collect(Collectors.groupingBy(AuditEventType::category));
        List<AuditCategoryOption> options = new ArrayList<>();
        for (AuditCategory category : AuditCategory.values()) {
            List<AuditEventType> events = byCategory.get(category);
            if (events == null) {
                continue;
            }
            boolean enabled = events.stream().anyMatch(event -> !viewer.featureOff(event.featureKey()));
            if (enabled || viewer.superAdmin()) {
                options.add(new AuditCategoryOption(category.name(), category.label(), sharedFeatureKey(events),
                        enabled));
            }
        }
        return options;
    }

    /** The action codes the reader may filter by, sorted. */
    public List<String> actions(Viewer viewer) {
        return offered(viewer, AuditEventType::action);
    }

    /** The resource types the reader may filter by, sorted. */
    public List<String> resourceTypes(Viewer viewer) {
        return offered(viewer, event -> event.resourceType().name());
    }

    private static List<String> offered(Viewer viewer, Function<AuditEventType, String> option) {
        return customerEvents().stream()
                .filter(event -> viewer.offersOptionsOf(event.featureKey()))
                .map(option)
                .collect(Collectors.toCollection(TreeSet::new))
                .stream().toList();
    }

    /**
     * The kinds of read the Access view filters by ({@code /access/activities}): the catalog's
     * {@link AuditCategory#ACCESS} events, without those of features that are off for the organization (super
     * admins see all).
     */
    public List<String> accessActivities(Viewer viewer) {
        return Arrays.stream(AuditEventType.values())
                .filter(event -> event.category() == AuditCategory.ACCESS)
                .filter(event -> viewer.offersOptionsOf(event.featureKey()))
                .map(AuditEventType::key)
                .collect(Collectors.toCollection(TreeSet::new))
                .stream().toList();
    }

    /**
     * Every category the platform view filters by, internal ones and the Access view's included, each marked
     * whether it is on for the organization read ({@code enabled}; always on for every organization).
     */
    public List<AuditCategoryOption> platformCategories(Viewer viewer) {
        Map<AuditCategory, List<AuditEventType>> byCategory = Arrays.stream(AuditEventType.values())
                .collect(Collectors.groupingBy(AuditEventType::category));
        List<AuditCategoryOption> options = new ArrayList<>();
        for (AuditCategory category : AuditCategory.values()) {
            List<AuditEventType> events = byCategory.get(category);
            if (events != null) {
                boolean enabled = events.stream().anyMatch(event -> !viewer.featureOff(event.featureKey()));
                options.add(new AuditCategoryOption(category.name(), category.label(), sharedFeatureKey(events),
                        enabled));
            }
        }
        return options;
    }

    /** Every action code a row can carry, internal ones included, sorted. */
    public List<String> platformActions() {
        return everyOption(AuditEventType::action);
    }

    /** Every resource type a row can carry, internal ones included, sorted. */
    public List<String> platformResourceTypes() {
        return everyOption(event -> event.resourceType().name());
    }

    private static List<String> everyOption(Function<AuditEventType, String> option) {
        return Arrays.stream(AuditEventType.values()).map(option)
                .collect(Collectors.toCollection(TreeSet::new))
                .stream().toList();
    }

    /**
     * The events the list's options describe: the customer catalog without {@link AuditCategory#ACCESS}, whose
     * sensitive reads the default list leaves out (they are the Access view's).
     */
    static List<AuditEventType> customerEvents() {
        return Arrays.stream(AuditEventType.values())
                .filter(event -> event.visibility() == AuditVisibility.CUSTOMER)
                .filter(event -> event.category() != AuditCategory.ACCESS)
                .toList();
    }

    /** The one feature every event of a category belongs to, or {@code null} (core, or several). */
    private static String sharedFeatureKey(List<AuditEventType> events) {
        Set<String> keys = events.stream().map(AuditEventType::featureKey).collect(Collectors.toSet());
        if (keys.size() != 1) {
            return null;
        }
        return keys.iterator().next();
    }

    /** One reader's view of the trail. */
    public static final class Viewer {

        private final boolean superAdmin;
        private final Long organizationId;
        private final Function<Long, Set<String>> disabledFeatureKeys;
        private final BiFunction<Collection<Long>, Collection<String>, Map<Long, Set<String>>> batch;
        /** Answers {@link #prefetch} loaded: per organization, the keys asked about and those off. */
        private final Map<Long, Set<String>> prefetchedKeys = new HashMap<>();
        private final Map<Long, Set<String>> prefetchedOff = new HashMap<>();

        Viewer(boolean superAdmin, Long organizationId, Function<Long, Set<String>> disabledFeatureKeys,
               BiFunction<Collection<Long>, Collection<String>, Map<Long, Set<String>>> batch) {
            this.superAdmin = superAdmin;
            this.organizationId = organizationId;
            this.disabledFeatureKeys = disabledFeatureKeys;
            this.batch = batch;
        }

        /**
         * Loads the feature states a page spanning several organizations needs, in one batched lookup
         * (four queries per feature key, however many organizations), instead of one per organization.
         * A reader of a single organization needs none: its one lookup is cached.
         *
         * @param featureKeysByOrganization the feature keys of the page's rows, by the rows' organization
         */
        public void prefetch(Map<Long, Set<String>> featureKeysByOrganization) {
            if (organizationId != null) {
                return;
            }
            Map<Long, Set<String>> wanted = new HashMap<>();
            featureKeysByOrganization.forEach((org, keys) -> {
                if (org != null && !keys.isEmpty()) {
                    wanted.put(org, keys);
                }
            });
            if (wanted.isEmpty()) {
                return;
            }
            Set<String> keys = new TreeSet<>();
            wanted.values().forEach(keys::addAll);
            Map<Long, Set<String>> off = batch.apply(wanted.keySet(), keys);
            wanted.keySet().forEach(org -> {
                prefetchedKeys.put(org, keys);
                prefetchedOff.put(org, off.getOrDefault(org, Set.of()));
            });
        }

        public boolean superAdmin() {
            return superAdmin;
        }

        public Long organizationId() {
            return organizationId;
        }

        /** The features off for the organization read; empty for a super admin reading every organization. */
        public Set<String> disabledFeatureKeys() {
            return disabledFeatureKeys.apply(organizationId);
        }

        /**
         * The features whose events the list leaves out. Empty: every event stays listed. The
         * one line to change to hide them too is here (see the class comment of the policy).
         */
        public Set<String> hiddenFeatureKeys() {
            return Set.of();
        }

        /** Whether {@code featureKey} is off for the organization read; a core event ({@code null}) never is. */
        public boolean featureOff(String featureKey) {
            return featureOff(organizationId, featureKey);
        }

        /** Whether {@code featureKey} is off for {@code rowOrganizationId}, the trail a listed row belongs to. */
        public boolean featureOff(Long rowOrganizationId, String featureKey) {
            if (featureKey == null || rowOrganizationId == null) {
                return false;
            }
            Set<String> prefetched = prefetchedKeys.get(rowOrganizationId);
            if (prefetched != null && prefetched.contains(featureKey)) {
                return prefetchedOff.get(rowOrganizationId).contains(featureKey);
            }
            return disabledFeatureKeys.apply(rowOrganizationId).contains(featureKey);
        }

        /** Whether the filter options of {@code featureKey}'s events are offered. */
        public boolean offersOptionsOf(String featureKey) {
            return superAdmin || !featureOff(featureKey);
        }

        @Override
        public String toString() {
            return "Viewer[superAdmin=" + superAdmin + ", organizationId=" + Objects.toString(organizationId) + "]";
        }
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.notification;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.certmanagement.constants.FeatureFlags.NOTIFICATION_PREFERENCES;

/**
 * An organization's notification settings: the {@link NotificationCategory categories} its admins
 * turned off, and the one decision every delivery asks, email (through the notifier's
 * {@code NotificationPolicyService} call) and the organization's integrations alike.
 *
 * <p>The settings apply only while {@code NOTIFICATION_PREFERENCES} is on for the organization, a flag
 * only a super admin decides. While it is off every notification is sent and the settings cannot be
 * read or changed; what was saved is kept and applies again when the flag comes back on.
 */
@Slf4j
@Service
public class NotificationPreferenceService {

    static final String CHECK_FAILED_METRIC = "certping.notifications.preference_check_failed";
    static final String SUPPRESSED_METRIC = "certping.notifications.suppressed";
    private static final String SEPARATOR = ",";

    private final FeatureFlagService featureFlags;
    private final OrganizationRepository organizations;
    private final OrganizationAuditRecorder organizationAudit;
    private final MeterRegistry meters;

    public NotificationPreferenceService(FeatureFlagService featureFlags, OrganizationRepository organizations,
                                         OrganizationAuditRecorder organizationAudit, MeterRegistry meters) {
        this.featureFlags = featureFlags;
        this.organizations = organizations;
        this.organizationAudit = organizationAudit;
        this.meters = meters;
    }

    /**
     * Whether the organization's notification of {@code action} may be delivered. False only when the
     * action's category is turned off and the organization may use notification settings. An action
     * outside every category is allowed without a read. Any failure to tell is an answer of true,
     * counted ({@value #CHECK_FAILED_METRIC}): a lost setting sends one informational notice too many,
     * while a lost answer must never drop one that matters.
     */
    public boolean allows(long organizationId, String action) {
        Optional<NotificationCategory> category = NotificationCategory.of(action);
        if (category.isEmpty()) {
            return true;
        }
        try {
            return !featureFlags.isEnabled(NOTIFICATION_PREFERENCES, organizationId)
                    || !parse(organizations.findMutedNotificationCategories(organizationId).orElse(""))
                            .contains(category.get());
        } catch (RuntimeException e) {
            meters.counter(CHECK_FAILED_METRIC).increment();
            log.warn("Notification settings unreadable for orgId={}, action={}; delivering: {}",
                    organizationId, action, e.getMessage());
            return true;
        }
    }

    /** Counts and logs one delivery of {@code action} on {@code channel} left out by the organization's settings. */
    public void recordSuppressed(long organizationId, String action, String channel) {
        String category = NotificationCategory.of(action).map(Enum::name).orElse("NONE");
        meters.counter(SUPPRESSED_METRIC, "channel", channel, "category", category).increment();
        log.info("Notification not delivered, category turned off: orgId={}, action={}, category={}, channel={}",
                organizationId, action, category, channel);
    }

    /**
     * The categories the organization turned off.
     *
     * @throws com.certmanagement.exception.FeatureDisabledException while notification settings are off for it
     * @throws ResourceNotFoundException for a deleted or unknown organization
     */
    @Transactional(readOnly = true)
    public Set<NotificationCategory> muted(long organizationId) {
        featureFlags.assertEnabled(NOTIFICATION_PREFERENCES, organizationId);
        return parse(organizations.findMutedNotificationCategories(organizationId)
                .orElseThrow(() -> notFound(organizationId)));
    }

    /**
     * Replaces the categories the organization turned off with {@code names}, audited when it changes
     * anything. The row is locked first, so two admins saving at once leave one complete answer.
     *
     * @throws BadRequestException for a missing list, or a name that is not a category or comes twice
     * @throws com.certmanagement.exception.FeatureDisabledException while notification settings are off for it
     * @throws ResourceNotFoundException for a deleted or unknown organization
     */
    @Transactional
    public Set<NotificationCategory> replaceMuted(long organizationId, Collection<String> names) {
        featureFlags.assertEnabled(NOTIFICATION_PREFERENCES, organizationId);
        Set<NotificationCategory> muted = validated(names);
        String before = organizations.lockMutedNotificationCategories(organizationId)
                .orElseThrow(() -> notFound(organizationId));
        String after = join(muted);
        if (!after.equals(before)) {
            organizations.updateMutedNotificationCategories(organizationId, after);
            organizationAudit.notificationSettingsChanged(organizationId, before, after);
        }
        return muted;
    }

    private static Set<NotificationCategory> validated(Collection<String> names) {
        if (names == null) {
            throw new BadRequestException("muted is required");
        }
        Set<NotificationCategory> muted = EnumSet.noneOf(NotificationCategory.class);
        for (String name : names) {
            NotificationCategory category = NotificationCategory.named(name)
                    .orElseThrow(() -> new BadRequestException("Unknown notification category"));
            if (!muted.add(category)) {
                throw new BadRequestException("A notification category is listed twice");
            }
        }
        return muted;
    }

    /** The stored list; a name that is no longer a category is ignored. */
    private static Set<NotificationCategory> parse(String stored) {
        Set<NotificationCategory> muted = EnumSet.noneOf(NotificationCategory.class);
        Arrays.stream(stored.split(SEPARATOR))
                .map(NotificationCategory::named)
                .flatMap(Optional::stream)
                .forEach(muted::add);
        return muted;
    }

    private static String join(Set<NotificationCategory> muted) {
        return muted.stream().map(Enum::name).collect(Collectors.joining(SEPARATOR));
    }

    private static ResourceNotFoundException notFound(long organizationId) {
        return new ResourceNotFoundException("Organization not found: " + organizationId);
    }
}

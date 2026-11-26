// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.enums.EventSource;
import com.certmanagement.messaging.OrgAdminNotificationPublisher;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.lifecycle.FeatureLifecycleState.Transition;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Sends the one FEATURE_PAUSED / FEATURE_RESUMED email owed for a platform transition to the
 * organization's admins, after the transition committed, and records that it went out.
 *
 * <p>Delivery is at least once with a deterministic key: the email is published, then marked sent.
 * A crash in between leaves it owed, the backstop publishes it again under the same
 * {@link FeatureLifecycleState#idempotencyKey()}, and the notifier delivers each key once
 * ({@code deliverOnce}), so pods and retries never send a second email.
 *
 * <p>A PAUSED email is first claimed in its own statement ({@link FeatureLifecycleStateStore#claimPausedNotice});
 * a resume that won the race withdraws it instead, and a resume that comes after the claim owes the
 * RESUMED email, so a customer told "paused" is always told "resumed". Called outside any transaction.
 */
@Slf4j
@Component
class FeatureLifecycleNotifier {

    static final String FEATURE_PAUSED = "FEATURE_PAUSED";
    static final String FEATURE_RESUMED = "FEATURE_RESUMED";

    private final ObjectProvider<OrgAdminNotificationPublisher> publisher;
    private final GlobalFeatureFlagRepository globalFlags;
    private final OrganizationRepository organizations;
    private final FeatureLifecycleStateStore states;

    FeatureLifecycleNotifier(ObjectProvider<OrgAdminNotificationPublisher> publisher,
                             GlobalFeatureFlagRepository globalFlags, OrganizationRepository organizations,
                             FeatureLifecycleStateStore states) {
        this.publisher = publisher;
        this.globalFlags = globalFlags;
        this.organizations = organizations;
        this.states = states;
    }

    /**
     * Publishes the email {@code state} owes, if any, then marks it sent. Never throws: a failure leaves
     * it owed for the backstop.
     */
    void sendOwed(FeatureLifecycleState state) {
        if (!state.isNotificationOwed()) {
            return;
        }
        try {
            if (state.pendingTransition() == Transition.PAUSED
                    && !states.claimPausedNotice(state.organizationId(), state.featureKey(), state.transitionSeq())) {
                log.info("[FeatureLifecycle] email {} withdrawn: the feature was resumed first", state.idempotencyKey());
                return;
            }
            OrgAdminNotificationPublisher sender = publisher.getIfAvailable();
            if (sender == null) {
                log.debug("[FeatureLifecycle] no notification sender configured; {} not emailed", state.idempotencyKey());
            } else {
                sender.publishOnceToOrgAdmins(action(state.pendingTransition()),
                        String.valueOf(state.organizationId()), EventSource.CERT_MANAGER.value(),
                        templateFields(state), state.idempotencyKey());
            }
            states.markNotified(state.organizationId(), state.featureKey(), state.transitionSeq());
        } catch (RuntimeException e) {
            log.warn("[FeatureLifecycle] email {} not sent yet, the backstop retries it: {}",
                    state.idempotencyKey(), e.getMessage());
        }
    }

    /** The notifier's payload: everything it renders comes from templateFields. */
    Map<String, Object> templateFields(FeatureLifecycleState state) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("organizationId", state.organizationId());
        fields.put("organizationName", organizations.findNameById(state.organizationId()).orElse(""));
        fields.put("featureKey", state.featureKey());
        fields.put("featureName", globalFlags.findByFeatureKey(state.featureKey())
                .map(GlobalFeatureFlag::getDisplayName).orElse(state.featureKey()));
        fields.put("items", items(state.pendingItems()));
        fields.put("occurredAt", state.pendingOccurredAt() == null ? null : state.pendingOccurredAt().toString());
        fields.put("idempotencyKey", state.idempotencyKey());
        return fields;
    }

    private static List<Map<String, Object>> items(List<AffectedItems> affected) {
        return affected.stream()
                .map(item -> Map.<String, Object>of("label", item.label(), "count", item.count()))
                .toList();
    }

    private static String action(Transition transition) {
        return transition == Transition.PAUSED ? FEATURE_PAUSED : FEATURE_RESUMED;
    }
}

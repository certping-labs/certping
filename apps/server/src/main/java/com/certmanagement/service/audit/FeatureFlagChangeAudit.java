// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditSubject;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Audits every feature flag write — global, org-type default, org override (org admin or super
 * admin) and their removals — and what the feature lifecycle did because of them (bulk clears,
 * platform pauses and resumes), with the state before and after, the operator's reason and the acting
 * user. Rows are written in the caller's transaction, so a flag change and its audit row commit or roll
 * back together. Where they land:
 * <ul>
 *   <li>a global or org-type change concerns no single organization: an internal row, with the operator's
 *       reason, for the platform's eyes ({@link AuditEvents#platformOnly});</li>
 *   <li>an organization's override, a bulk clear, a pause or a resume: that organization's trail. The
 *       operator's free-text reason is an internal-only attribute of the catalog, so it is never shown there;</li>
 *   <li>a pause or a resume is CertPing acting ({@code feature-lifecycle-*} jobs): the administrator whose
 *       change triggered it, if any, is kept by id as {@code requestedBy}, and what was paused or resumed as
 *       {@code items} ("12 deployments, 3 monitors").</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class FeatureFlagChangeAudit {

    /** The job a pause or a resume forced by a flag change acts as. */
    static final String TRANSITIONS_JOB = "feature-lifecycle-transitions";
    /** The job the baseline pause acts as. */
    static final String BASELINE_JOB = "feature-lifecycle-reconcile";

    /** Bounds what an operator's free-text note can put into one audit row. */
    static final int MAX_REASON_LENGTH = 500;

    /** Which layer of the flag decision changed. */
    public enum Level { GLOBAL, ORG_TYPE, ORGANIZATION }

    private final AuditRecorder recorder;

    /** The global switch changed; {@code resourceId} is the {@code global_feature_flags} row. */
    public void recordGlobal(Long resourceId, String featureKey, boolean before, boolean after, String reason) {
        Map<String, String> attributes = attributes(Level.GLOBAL, null, reason);
        recorder.record(AuditEvents.platformOnly(AuditEventType.FEATURE_CHANGED, flag(resourceId, featureKey, null)
                .enabled(after).changes(stateChanges(Map.of("enabled", before), Map.of("enabled", after)))
                .attributes(attributes).build()));
    }

    /** An org-type default was set ({@code before == null}: created) or removed ({@code after == null}). */
    public void recordOrgType(Long resourceId, String orgType, String featureKey,
                              Boolean before, Boolean after, String reason) {
        AuditSubject.AuditSubjectBuilder subject = flag(resourceId, featureKey, null)
                .attributes(attributes(Level.ORG_TYPE, orgType, reason));
        recorder.record((after == null
                ? AuditEvents.platformOnly(AuditEventType.FEATURE_OVERRIDE_REMOVED, subject.build())
                : AuditEvents.platformOnly(AuditEventType.FEATURE_CHANGED, subject.enabled(after)
                        .changes(stateChanges(before == null ? null : Map.of("enabled", before),
                                Map.of("enabled", after))).build())));
    }

    /** An org override was set ({@code before == null}: created) or removed ({@code after == null}). */
    public void recordOrganization(Long resourceId, Long organizationId, String featureKey,
                                   OverrideState before, OverrideState after, String reason) {
        // The operator's reason is internal-only in the catalog: this customer row drops it.
        AuditSubject.AuditSubjectBuilder subject = flag(resourceId, featureKey, organizationId)
                .attributes(attributes(Level.ORGANIZATION, null, reason));
        recorder.record((after == null
                ? AuditEvents.success(AuditEventType.FEATURE_OVERRIDE_REMOVED, subject.build())
                : AuditEvents.success(AuditEventType.FEATURE_CHANGED, subject.enabled(after.enabled())
                        .changes(stateChanges(before == null ? null : before.asMap(), after.asMap())).build())));
    }

    /**
     * An organization admin cleared a blocker in bulk before switching the feature off; the actor
     * comes from the current request.
     */
    public void recordClear(Long organizationId, String featureKey, String kind, String action, int affected) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("kind", kind);
        attributes.put("action", action);
        recorder.record(AuditEvents.success(AuditEventType.FEATURE_RECORDS_CLEARED, flag(null, featureKey, organizationId)
                .count(affected).attributes(attributes).build()));
    }

    /**
     * The platform paused or resumed a feature's records for an organization because the feature was
     * switched off or on by someone other than the organization's admin.
     *
     * @param paused      true for a pause, false for a resume
     * @param items       per kind, what changed: {@code {kind, label, count}}
     * @param actorUserId the administrator whose flag change triggered it, or null for the reconciler
     */
    public void recordPlatformTransition(Long organizationId, String featureKey, boolean paused,
                                         List<Map<String, Object>> items, Integer actorUserId) {
        recordPlatformTransition(organizationId, featureKey, paused, null, items, actorUserId);
    }

    /**
     * {@link #recordPlatformTransition} for a forced pause, naming the flag that was switched off when it is
     * not the feature's own: the DNS credentials automatic renewal requires.
     *
     * @param causeFeatureKey the flag switched off, or null when it is the feature itself
     */
    public void recordForcedPause(Long organizationId, String featureKey, String causeFeatureKey,
                                  List<Map<String, Object>> items, Integer actorUserId) {
        recordPlatformTransition(organizationId, featureKey, true, causeFeatureKey, items, actorUserId);
    }

    private void recordPlatformTransition(Long organizationId, String featureKey, boolean paused,
                                          String causeFeatureKey, List<Map<String, Object>> items,
                                          Integer actorUserId) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "items", itemsText(items));
        put(attributes, "cause", causeFeatureKey);
        put(attributes, "requestedBy", actorUserId == null ? null : actorUserId.toString());
        recordAsSystem(TRANSITIONS_JOB, organizationId, paused ? AuditEventType.FEATURE_PAUSED
                : AuditEventType.FEATURE_RESUMED, flag(null, featureKey, organizationId).count(itemCount(items))
                .attributes(attributes).build());
    }

    /**
     * The baseline paused an organization's records silently: the feature was already off for it
     * (by {@code cause}) before any super admin change the lifecycle applies. One row per organization.
     *
     * @param cause the layer that has it off: GLOBAL, CATEGORY, ORG_OVERRIDE or ORG_TYPE
     * @param items per kind, what was paused: {@code {kind, label, count}}
     */
    public void recordBaselinePause(Long organizationId, String featureKey, String cause,
                                    List<Map<String, Object>> items) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "items", itemsText(items));
        put(attributes, "cause", cause);
        recordAsSystem(BASELINE_JOB, organizationId, AuditEventType.FEATURE_PAUSED, flag(null, featureKey,
                organizationId).count(itemCount(items)).attributes(attributes).build());
    }

    /** An org override's audited columns. */
    public record OverrideState(boolean enabled, boolean adminLocked) {
        Map<String, Object> asMap() {
            Map<String, Object> state = new LinkedHashMap<>();
            state.put("enabled", enabled);
            state.put("adminLocked", adminLocked);
            return state;
        }
    }

    private void recordAsSystem(String job, Long organizationId, AuditEventType type, AuditSubject subject) {
        AuditEventRow row;
        try (AuditScope scope = AuditScope.system(job, organizationId)) {
            row = AuditEvents.success(type, subject);
        }
        recorder.record(row);
    }

    /** The flag as a target: its row id, its key as the name the sentence quotes. */
    private static AuditSubject.AuditSubjectBuilder flag(Long resourceId, String featureKey, Long organizationId) {
        return AuditSubject.builder().organizationId(organizationId).resourceId(resourceId).resourceRef(featureKey)
                .name(featureKey);
    }

    private static Map<String, String> attributes(Level level, String orgType, String reason) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("level", level.name());
        put(attributes, "orgType", orgType);
        put(attributes, "reason", normalizeReason(reason));
        return attributes;
    }

    /** The on/off and lock state that changed; a field absent before (a new override) reads as no value. */
    private static List<AuditChange> stateChanges(Map<String, Object> before, Map<String, Object> after) {
        List<AuditChange> changes = new ArrayList<>();
        for (Map.Entry<String, Object> field : after.entrySet()) {
            String was = before == null || before.get(field.getKey()) == null ? null
                    : before.get(field.getKey()).toString();
            String now = Objects.toString(field.getValue(), null);
            if (!Objects.equals(was, now)) {
                changes.add(new AuditChange(field.getKey(), was, now));
            }
        }
        return changes;
    }

    /** "12 deployments, 3 monitors": what a pause or resume changed, per kind. */
    private static String itemsText(List<Map<String, Object>> items) {
        if (items == null) {
            return null;
        }
        List<String> parts = new ArrayList<>(items.size());
        for (Map<String, Object> item : items) {
            Object label = item.get("label");
            if (label != null) {
                Object count = item.get("count");
                parts.add(count == null ? label.toString() : count + " " + label);
            }
        }
        return parts.isEmpty() ? null : String.join(", ", parts);
    }

    private static Integer itemCount(List<Map<String, Object>> items) {
        if (items == null) {
            return null;
        }
        int total = 0;
        for (Map<String, Object> item : items) {
            if (item.get("count") instanceof Number count) {
                total += count.intValue();
            }
        }
        return total;
    }

    private static void put(Map<String, String> attributes, String name, String value) {
        if (value != null && !value.isBlank()) {
            attributes.put(name, value);
        }
    }

    static String normalizeReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return null;
        }
        String trimmed = reason.strip();
        return trimmed.length() <= MAX_REASON_LENGTH ? trimmed : trimmed.substring(0, MAX_REASON_LENGTH);
    }
}

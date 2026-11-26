// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.entity.Organization;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Writes the organization events of the audit trail: an organization created, its settings changed, deleted;
 * removed records permanently deleted and how long they are kept; and the platform settings a super admin
 * changes, which belong to no customer's trail.
 *
 * <p>Every row is written in the change's own transaction ({@link AuditRecorder#record}, which requires one).
 *
 * <p>An organization's name is never stored (it is rendered live when read): a rename is kept as the field
 * name only. Only the settings on {@link AuditEventType#ORGANIZATION_UPDATED}'s allow-list keep their values.
 */
@Component
public class OrganizationAuditRecorder {

    private final AuditRecorder recorder;

    public OrganizationAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    /** {@code organization} was created; the row lands in its own trail. */
    public void organizationCreated(Organization organization) {
        recorder.record(AuditEvents.success(AuditEventType.ORGANIZATION_CREATED,
                organization(organization.getId()).build()));
    }

    /**
     * Organization {@code organizationId}'s settings changed.
     *
     * @param renamed whether its name changed: kept as the field name, never the names
     */
    public void organizationUpdated(long organizationId, boolean renamed, String domainBefore, String domainAfter,
                                    Boolean activeBefore, Boolean activeAfter) {
        List<AuditChange> changes = new ArrayList<>();
        if (renamed) {
            changes.add(new AuditChange("name", null, null));
        }
        change(changes, "domain", domainBefore, domainAfter);
        change(changes, "active", activeBefore, activeAfter);
        recorder.record(AuditEvents.success(AuditEventType.ORGANIZATION_UPDATED, organization(organizationId)
                .changes(changes).build()));
    }

    /** Organization {@code organizationId} was deleted; the row stays in its trail until retention ends. */
    public void organizationDeleted(long organizationId) {
        recorder.record(AuditEvents.success(AuditEventType.ORGANIZATION_DELETED, organization(organizationId).build()));
    }

    /** {@code deleted} records organization {@code organizationId} removed more than {@code retentionDays} ago were purged. */
    public void recordsPurged(long organizationId, int retentionDays, int deleted) {
        recorder.record(AuditEvents.success(AuditEventType.DATA_RETENTION_PURGED, organization(organizationId)
                .count(deleted).attributes(Map.of("retentionDays", Integer.toString(retentionDays))).build()));
    }

    /**
     * How long organization {@code organizationId} keeps removed records changed; {@code null} is "the
     * platform's default".
     */
    public void retentionChanged(long organizationId, Integer daysBefore, Integer daysAfter) {
        List<AuditChange> changes = new ArrayList<>(1);
        change(changes, "retentionDays", daysBefore, daysAfter);
        recorder.record(AuditEvents.success(AuditEventType.DATA_RETENTION_CHANGED, organization(organizationId)
                .changes(changes).build()));
    }

    /**
     * The notification categories organization {@code organizationId} turned off changed; each list is
     * comma-joined, "" for none.
     */
    public void notificationSettingsChanged(long organizationId, String mutedBefore, String mutedAfter) {
        List<AuditChange> changes = new ArrayList<>(1);
        change(changes, "mutedCategories", mutedBefore, mutedAfter);
        recorder.record(AuditEvents.success(AuditEventType.NOTIFICATION_SETTINGS_CHANGED,
                organization(organizationId).changes(changes).build()));
    }

    /** The platform setting {@code key} changed: an internal row, for the platform's eyes only. */
    public void platformSettingChanged(String key, String before, String after) {
        List<AuditChange> changes = new ArrayList<>(1);
        change(changes, "value", before, after);
        recorder.record(AuditEvents.internal(AuditEventType.PLATFORM_SETTING_CHANGED, AuditSubject.builder()
                .resourceRef(key).name(key).changes(changes).build()));
    }

    private static AuditSubject.AuditSubjectBuilder organization(long organizationId) {
        return AuditSubject.builder().organizationId(organizationId).resourceId(organizationId);
    }

    private static void change(List<AuditChange> changes, String field, Object before, Object after) {
        String was = before == null ? null : before.toString();
        String now = after == null ? null : after.toString();
        if (!Objects.equals(was, now)) {
            changes.add(new AuditChange(field, was, now));
        }
    }
}

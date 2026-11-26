// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.GlobalSettingsEntity;
import com.certmanagement.entity.Organization;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.GlobalSettingsRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Manages global settings (e.g. {@code soft_delete_retention_days}) and per-organization
 * retention overrides.
 *
 * <p>Retention resolution priority (highest to lowest):
 * <ol>
 *   <li>Per-organization {@code soft_delete_retention_days} (not null)</li>
 *   <li>Global {@code soft_delete_retention_days} from {@code global_settings}</li>
 *   <li>Hard-coded fallback of 30 days</li>
 * </ol>
 *
 * <p>Both values are platform decisions: only a super admin sets them. The per-organization value may
 * be shorter than the global one, for example when an organization needs faster deletion.
 *
 * <p>Each change is audited in its transaction: the global value as an internal
 * {@code platform_setting.changed} row, an organization's as {@code data_retention.changed} in its trail.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GlobalSettingsService {

    static final String KEY_SOFT_DELETE_RETENTION_DAYS = "soft_delete_retention_days";
    static final int DEFAULT_RETENTION_DAYS = 30;
    static final int MIN_ORG_RETENTION_DAYS = 1;
    static final int MAX_ORG_RETENTION_DAYS = 3650;

    private final GlobalSettingsRepository globalSettingsRepository;
    private final OrganizationRepository organizationRepository;
    private final OrganizationAuditRecorder organizationAudit;

    // ------------------------------------------------------------------ //
    //  Global settings
    // ------------------------------------------------------------------ //

    @Transactional(readOnly = true)
    public int getGlobalRetentionDays() {
        return globalSettingsRepository.findById(KEY_SOFT_DELETE_RETENTION_DAYS)
                .map(s -> parseIntOrDefault(s.getValue(), DEFAULT_RETENTION_DAYS))
                .orElse(DEFAULT_RETENTION_DAYS);
    }

    @Transactional
    public void setGlobalRetentionDays(int days, Long updatedByUserId) {
        if (days < 1) {
            throw new com.certmanagement.exception.BadRequestException("Retention period must be at least 1 day");
        }
        int before = getGlobalRetentionDays();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        int rows = globalSettingsRepository.updateValue(
                KEY_SOFT_DELETE_RETENTION_DAYS, String.valueOf(days), now, updatedByUserId);
        if (rows == 0) {
            globalSettingsRepository.save(GlobalSettingsEntity.builder()
                    .key(KEY_SOFT_DELETE_RETENTION_DAYS)
                    .value(String.valueOf(days))
                    .description("Default days before soft-deleted records are hard-purged.")
                    .updatedAt(now)
                    .updatedBy(updatedByUserId)
                    .build());
        }
        organizationAudit.platformSettingChanged(KEY_SOFT_DELETE_RETENTION_DAYS, Integer.toString(before),
                Integer.toString(days));
        log.info("Global soft-delete retention set to {} days by userId={}", days, updatedByUserId);
    }

    // ------------------------------------------------------------------ //
    //  Per-organization settings
    // ------------------------------------------------------------------ //

    @Transactional(readOnly = true)
    public Integer getOrgRetentionDaysOverride(Long organizationId) {
        return organizationRepository.findById(organizationId)
                .map(Organization::getSoftDeleteRetentionDays)
                .orElse(null);
    }

    @Transactional
    public void setOrgRetentionDaysOverride(Long organizationId, Integer days) {
        if (days != null && (days < MIN_ORG_RETENTION_DAYS || days > MAX_ORG_RETENTION_DAYS)) {
            throw new com.certmanagement.exception.BadRequestException("Retention period must be between " + MIN_ORG_RETENTION_DAYS + " and "
                    + MAX_ORG_RETENTION_DAYS + " days, or null to use the global setting");
        }
        Organization org = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new ResourceNotFoundException("Organization not found: " + organizationId));
        Integer before = org.getSoftDeleteRetentionDays();
        org.setSoftDeleteRetentionDays(days);
        organizationRepository.save(org);
        organizationAudit.retentionChanged(organizationId, before, days);
        log.info("Org {} soft-delete retention override set to {} days by userId={}",
                organizationId, days, GatewayRequestContext.getUserId());
    }

    // ------------------------------------------------------------------ //
    //  Resolved retention for purge operations
    // ------------------------------------------------------------------ //

    /**
     * Returns the effective retention period for an organization: its override when set, otherwise
     * the global setting.
     */
    @Transactional(readOnly = true)
    public int resolveRetentionDays(Long organizationId) {
        Integer orgOverride = getOrgRetentionDaysOverride(organizationId);
        return orgOverride != null ? orgOverride : getGlobalRetentionDays();
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            log.warn("global_settings contains non-numeric value '{}' for key soft_delete_retention_days — using default {}",
                    value, defaultValue);
            return defaultValue;
        }
    }
}

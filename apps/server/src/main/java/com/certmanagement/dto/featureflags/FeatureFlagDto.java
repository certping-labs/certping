// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import com.certmanagement.service.FeatureFlagService.ResolvedFlag;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

/**
 * Full feature flag response for the org-scoped listing endpoint.
 * Includes the global state, optional org-type override, optional org-level override,
 * and the resolved effective state.
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FeatureFlagDto {

    private String featureKey;
    private String displayName;
    private String description;
    /** Management scope: {@code ORG} or {@code PLATFORM}. */
    private String scope;
    /** Catalog category, for display: {@code PLATFORM} or {@code B2B}. */
    private String category;
    private boolean globalEnabled;
    /** The org type of the requesting organization; every organization is {@code B2B}. */
    private String orgType;
    /** Null when no org-type override has been set. */
    private Boolean orgTypeEnabled;
    /** Null when the org has no override. */
    private Boolean orgEnabled;
    /** True when a super admin set the org override: it outranks the org-type default and the org admin cannot change it. */
    private boolean adminLocked;
    /** The resolved effective state — what actually gates access. */
    private boolean effectiveEnabled;
    /** Whether the org admin may set this flag; false shows it read-only. */
    private boolean orgControllable;
    /**
     * Set when the flag is on but its automatic work is paused because the named flag is off (auto-renewal
     * while {@code DNS_CREDENTIALS} is off); null otherwise.
     */
    private String automaticWorkPausedBy;

    public static FeatureFlagDto from(ResolvedFlag resolved) {
        return FeatureFlagDto.builder()
                .featureKey(resolved.global().getFeatureKey())
                .displayName(resolved.global().getDisplayName())
                .description(resolved.global().getDescription())
                .scope(resolved.global().getScope())
                .category(resolved.global().getCategory())
                .globalEnabled(Boolean.TRUE.equals(resolved.global().getEnabled()))
                .orgType(resolved.orgType())
                .orgTypeEnabled(resolved.orgTypeEnabled())
                .orgEnabled(resolved.orgEnabled())
                .adminLocked(resolved.adminLocked())
                .effectiveEnabled(resolved.effectiveEnabled())
                .orgControllable(resolved.orgControllable())
                .automaticWorkPausedBy(resolved.automaticWorkPausedBy())
                .build();
    }
}

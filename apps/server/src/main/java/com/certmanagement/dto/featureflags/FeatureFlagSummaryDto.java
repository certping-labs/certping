// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One cell in the flags × orgs admin summary matrix.
 * Each entry represents the state of a single flag for a single organization,
 * including the org's type and any org-type-level override.
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FeatureFlagSummaryDto {

    private Long organizationId;
    private String organizationName;
    /** The type of this organization; every organization is {@code B2B}. */
    private String orgType;
    private String featureKey;
    /** Catalog category, for display: {@code PLATFORM} or {@code B2B}. */
    private String category;
    private boolean globalEnabled;
    /** Null when no org-type override has been set for this flag. */
    private Boolean orgTypeEnabled;
    /** Null when this organization has no org-specific override. */
    private Boolean orgEnabled;
    private boolean effectiveEnabled;
}

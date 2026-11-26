// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

/** Request body for enabling or disabling a feature flag. */
@Data
public class FeatureFlagUpdateRequest {

    @NotNull(message = "enabled must be specified")
    private Boolean enabled;

    /** Optional operator note, persisted in the change's audit row. */
    @Size(max = 500, message = "reason must be at most 500 characters")
    private String reason;
}

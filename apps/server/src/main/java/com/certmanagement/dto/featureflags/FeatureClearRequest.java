// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import com.certmanagement.service.lifecycle.BlockerKind;
import com.certmanagement.service.lifecycle.ClearAction;
import jakarta.validation.constraints.NotNull;

/** {@code POST /api/v1/feature-flags/{featureKey}/clear}: which records to clear, and how. */
public record FeatureClearRequest(@NotNull BlockerKind kind, @NotNull ClearAction action) {
}

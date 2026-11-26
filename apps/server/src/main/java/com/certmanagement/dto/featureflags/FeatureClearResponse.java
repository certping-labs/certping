// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import com.certmanagement.service.lifecycle.BlockerKind;
import com.certmanagement.service.lifecycle.ClearAction;

/** The result of a bulk clear: how many records the action changed. */
public record FeatureClearResponse(BlockerKind kind, ClearAction action, int affected) {
}

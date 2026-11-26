// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Deterministic profile-correlation outcome for one certificate candidate. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CertificateCorrelationResult(
        String certificateXref,
        String status,
        String providerProfileId,
        String providerProfileType,
        String matchMethod) {
}

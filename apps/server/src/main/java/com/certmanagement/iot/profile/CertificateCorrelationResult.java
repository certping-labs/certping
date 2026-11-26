// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Agent-reported exact match, non-match, or ambiguity for one certificate. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CertificateCorrelationResult(
        String certificateXref,
        String status,
        String providerProfileId,
        String providerProfileType,
        String matchMethod) {
}

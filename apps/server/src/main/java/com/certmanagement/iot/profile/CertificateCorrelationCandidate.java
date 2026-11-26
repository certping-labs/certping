// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Bounded certificate identity sent to the agent for Intune profile correlation. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CertificateCorrelationCandidate(
        String certificateXref,
        String fingerprintSha1,
        String issuerDn,
        String serialNumber) {
}

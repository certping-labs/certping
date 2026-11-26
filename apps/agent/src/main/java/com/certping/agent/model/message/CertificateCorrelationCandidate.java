// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Certificate identity that the server wants matched against Intune reporting data. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CertificateCorrelationCandidate(
        String certificateXref,
        String fingerprintSha1,
        String issuerDn,
        String serialNumber) {
}

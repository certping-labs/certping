// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/**
 * The Intune challenge (first enrolment) or the renewal-certificate check failed. Mapped to a signed
 * {@code CertRep FAILURE} with {@code failInfo = badMessageCheck}.
 */
public class ChallengeValidationException extends RuntimeException {
    public ChallengeValidationException(String message) {
        super(message);
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/**
 * Intune's SCEP validation service could not be reached, or refused the call for a transport/auth
 * reason rather than rejecting the challenge. Mapped to HTTP 503 so the SCEP client retries later.
 * The CA is never asked to sign and no {@code SendFailureNotification} is sent, because nothing was
 * decided about the request. Distinct from {@link ChallengeValidationException}, which is a real
 * rejection and returns a signed {@code CertRep FAILURE}.
 */
public class IntuneUnavailableException extends RuntimeException {
    public IntuneUnavailableException(String message) {
        super(message);
    }

    public IntuneUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}

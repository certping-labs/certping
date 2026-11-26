// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.scep.ChallengeValidationException;
import com.certping.agent.scep.ResolvedEndpoint;

/**
 * Validates the one-time SCEP challenge against Intune and reports issuance outcomes back.
 * Every operation is bound to the {@link ResolvedEndpoint} whose source route received the
 * request, so the correct Intune tenant credential is selected before any Microsoft call —
 * one agent can serve several Intune connections without guessing between credentials.
 *
 * <p>{@link MicrosoftIntuneScepValidator} is the production implementation. SCEP startup fails
 * when Intune validation is disabled, so an enrollment can never bypass its challenge check.
 */
public interface IntuneScepValidator {

    /**
     * Whether this validator actually submits the request to Microsoft. Only then may an identifier
     * carried by the validated challenge be published as {@code MICROSOFT_VALIDATED}.
     */
    default boolean validatesWithMicrosoft() {
        return false;
    }

    /** First enrolment: validate the challenge in the CSR against the endpoint's Intune tenant. */
    ScepValidationResult validate(ResolvedEndpoint endpoint, String transactionId, String csrBase64)
            throws ChallengeValidationException;

    /** Report a successful issuance so Intune marks the certificate delivered (8-arg contract). */
    void notifySuccess(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                       String thumbprint, String serial, String expiryIso, String issuer,
                       String caConfig, String certAuthority);

    void notifyFailure(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                       long hResult, String description);
}

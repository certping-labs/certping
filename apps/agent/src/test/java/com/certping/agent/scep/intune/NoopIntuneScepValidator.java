// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.scep.ResolvedEndpoint;

/** Test fixture for protocol tests that do not exercise Microsoft's external service. */
public class NoopIntuneScepValidator implements IntuneScepValidator {
    @Override
    public ScepValidationResult validate(
            ResolvedEndpoint endpoint, String transactionId, String csrBase64) {
        return ScepValidationResult.absent();
    }

    @Override
    public void notifySuccess(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                              String thumbprint, String serial, String expiryIso, String issuer,
                              String caConfig, String certAuthority) {
    }

    @Override
    public void notifyFailure(ResolvedEndpoint endpoint, String transactionId, String csrBase64,
                              long hResult, String description) {
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import java.time.Duration;

/**
 * Looks up what the MDM says about the certificate profiles pointing at one SCEP endpoint. The
 * SCEP request itself never names its profile, so every value is a hint and may be absent.
 * Implementations must not throw: a failed lookup returns {@link ScepProfileHint#NONE}.
 */
public interface ScepProfileHintResolver {

    ScepProfileHintResolver NONE = endpoint -> ScepProfileHint.NONE;

    ScepProfileHint resolve(ResolvedEndpoint endpoint);

    /**
     * @param providerProfileId the MDM profile id, only when exactly one profile uses the endpoint
     * @param validity the certificate lifetime, only when every such profile agrees on it
     */
    record ScepProfileHint(String providerProfileId, Duration validity) {
        public static final ScepProfileHint NONE = new ScepProfileHint(null, null);
    }
}

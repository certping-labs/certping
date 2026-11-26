// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import java.security.cert.X509Certificate;
import java.util.List;

public record SmallstepSignResult(
        List<X509Certificate> chain,
        String authorityName,
        String provisionerName) {
    public X509Certificate leaf() { return chain.getFirst(); }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Certificate material as the agent stores it: the chain, leaf first, and the leaf's private key.
 *
 * @param chain      leaf first, then intermediates; never empty
 * @param privateKey the leaf's key, or {@code null} when the key is held outside the platform
 */
record AgentCertificateBundle(List<X509Certificate> chain, PrivateKey privateKey) {

    AgentCertificateBundle {
        chain = List.copyOf(chain);
    }

    X509Certificate leaf() {
        return chain.get(0);
    }

    boolean hasPrivateKey() {
        return privateKey != null;
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.scep.RaIdentity;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

/** Test-only SCEP issuer used to exercise protocol encoding without an external CA. */
public final class NoopScepCaBackend implements ScepCaBackend {
    private final KeyPair caKeys = DevCa.rootKeyPair();
    private final X509Certificate caCert = DevCa.root(caKeys, "CN=CertPing Test SCEP CA");
    private final RaIdentity ra = DevCa.issueRa(caCert, caKeys, "CN=CertPing Test SCEP RA");

    @Override
    public IssuedCertificate sign(PKCS10CertificationRequest csr, Duration validity) throws CaException {
        try {
            X509Certificate leaf = DevCa.sign(csr, caCert, caKeys.getPrivate());
            return new IssuedCertificate(List.of(leaf, caCert),
                    leaf.getSubjectX500Principal().getName(), null);
        } catch (Exception exception) {
            throw new CaException("test signing failed", exception);
        }
    }

    @Override
    public void assertRenewalAllowed(X509Certificate priorCertificate) {
        // The test fixture has no external revocation service. Production has no such backend.
    }

    @Override
    public X509Certificate getRaCertificate() {
        return ra.cert();
    }

    @Override
    public PrivateKey getRaPrivateKey() {
        return ra.key();
    }

    @Override
    public List<X509Certificate> getCaChain() {
        return List.of(caCert);
    }
}

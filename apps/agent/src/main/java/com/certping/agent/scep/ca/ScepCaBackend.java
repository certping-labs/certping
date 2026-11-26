// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

/**
 * The pluggable "sign a CSR" backend behind the SCEP RA. Also owns the RA identity published via
 * {@code GetCACert} and used to decrypt requests and sign responses.
 */
public interface ScepCaBackend {

    /** RA encryption/signing cert — devices encrypt to it; its key signs the CertRep. */
    X509Certificate getRaCertificate();

    PrivateKey getRaPrivateKey();

    /** The issuing CA chain (published alongside the RA cert in GetCACert). */
    List<X509Certificate> getCaChain();

    /** Fail closed before signing a renewal when the presented certificate is revoked. */
    void assertRenewalAllowed(X509Certificate priorCertificate) throws CaException;

    /**
     * Sign the approved CSR; returns the issued leaf, chain, and backend identifiers. A null
     * {@code validity} leaves the lifetime to the CA's own default.
     */
    IssuedCertificate sign(PKCS10CertificationRequest csr, Duration validity) throws CaException;
}

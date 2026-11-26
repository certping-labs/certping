// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/** Parses and verifies CRL data without trusting the step-ca transport response itself. */
@Slf4j
final class SmallstepCrlVerifier {
    private SmallstepCrlVerifier() {}

    static X509CRL parse(byte[] encoded) {
        try {
            return (X509CRL) CertificateFactory.getInstance("X.509")
                    .generateCRL(new ByteArrayInputStream(encoded));
        } catch (Exception exception) {
            throw new TransientAgentException("SMALLSTEP_CRL_INVALID",
                    "Smallstep returned an unreadable CRL", exception);
        }
    }

    static Status status(X509CRL crl, String expectedIssuerDn, BigInteger serial,
                         X509Certificate issuer, Instant now) {
        X500Principal expectedIssuer;
        try {
            expectedIssuer = new X500Principal(expectedIssuerDn);
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException("SMALLSTEP_CERTIFICATE_ISSUER_INVALID",
                    "The Smallstep certificate issuer DN is invalid", exception);
        }
        if (!expectedIssuer.equals(crl.getIssuerX500Principal())) {
            throw new PermanentAgentException("SMALLSTEP_CERTIFICATE_ISSUER_MISMATCH",
                    "The certificate issuer does not match the Smallstep CRL issuer");
        }
        verify(crl, issuer, now);
        X509CRLEntry entry = crl.getRevokedCertificate(serial);
        if (entry == null) return new Status(false, null, null);
        String reason = entry.getRevocationReason() == null
                ? "UNSPECIFIED" : entry.getRevocationReason().name();
        return new Status(true, reason, entry.getRevocationDate().toInstant().toString());
    }

    static List<X509Certificate> trustedIntermediates(
            String rootPem, JsonNode certificates) {
        if (!certificates.isArray() || certificates.isEmpty()) {
            throw new PermanentAgentException("SMALLSTEP_INTERMEDIATE_MISSING",
                    "Smallstep returned no issuing intermediate certificate");
        }
        try {
            X509Certificate root = parseCertificate(rootPem);
            List<X509Certificate> verified = new ArrayList<>();
            for (JsonNode certificate : certificates) {
                try {
                    X509Certificate intermediate = parseCertificate(certificate.asString());
                    if (intermediate.getBasicConstraints() < 0
                            || !intermediate.getIssuerX500Principal()
                                    .equals(root.getSubjectX500Principal())) continue;
                    intermediate.verify(root.getPublicKey());
                    verified.add(intermediate);
                } catch (Exception exception) {
                    // Rotation responses can briefly contain both retired and current issuers.
                    // Trust every independently verified candidate, never the response as a whole.
                    log.warn("Ignoring an invalid Smallstep intermediate certificate: {}",
                            exception.getMessage());
                }
            }
            if (verified.isEmpty()) {
                throw new PermanentAgentException("SMALLSTEP_INTERMEDIATE_UNTRUSTED",
                        "Smallstep returned no intermediate signed by the configured root");
            }
            return List.copyOf(verified);
        } catch (PermanentAgentException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_INTERMEDIATE_INVALID",
                    "Could not validate the Smallstep issuing intermediate", exception);
        }
    }

    private static void verify(X509CRL crl, X509Certificate issuer, Instant now) {
        Date thisUpdate = crl.getThisUpdate();
        Date nextUpdate = crl.getNextUpdate();
        if (thisUpdate == null || thisUpdate.toInstant().isAfter(now.plusSeconds(300))
                || nextUpdate == null || !nextUpdate.toInstant().isAfter(now)) {
            throw new TransientAgentException("SMALLSTEP_CRL_STALE",
                    "Smallstep CRL is missing a valid freshness window");
        }
        try {
            issuer.checkValidity(Date.from(now));
            crl.verify(issuer.getPublicKey());
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_CRL_SIGNATURE_INVALID",
                    "Smallstep CRL signature verification failed", exception);
        }
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    record Status(boolean revoked, String reason, String observedAt) {}
}

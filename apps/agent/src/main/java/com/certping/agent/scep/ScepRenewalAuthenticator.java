// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Authenticates a SCEP renewal signer and prevents the CSR from claiming a new identity. */
final class ScepRenewalAuthenticator {

    private ScepRenewalAuthenticator() {
    }

    static X509Certificate authenticate(ResolvedEndpoint endpoint, ScepRequest request) {
        X509Certificate priorCertificate = request.deviceCertificate();
        requireCurrentlyValid(priorCertificate);
        requireConfiguredIssuerSignature(priorCertificate, endpoint.caChain());
        requireSameSubject(priorCertificate, request);
        requireNoNewSubjectAlternativeNames(priorCertificate, request);
        return priorCertificate;
    }

    private static void requireCurrentlyValid(X509Certificate certificate) {
        try {
            certificate.checkValidity();
        } catch (Exception exception) {
            throw new ChallengeValidationException("renewal certificate expired or not yet valid");
        }
    }

    private static void requireConfiguredIssuerSignature(X509Certificate certificate,
                                                          List<X509Certificate> caChain) {
        if (caChain == null || caChain.isEmpty()) {
            throw new ChallengeValidationException(
                    "renewal unavailable because no issuing CA certificate is configured");
        }
        boolean verified = caChain.stream().anyMatch(candidate -> verifiesWith(certificate, candidate));
        if (!verified) {
            throw new ChallengeValidationException("renewal certificate not issued by this CA");
        }
    }

    private static boolean verifiesWith(X509Certificate certificate, X509Certificate candidate) {
        if (candidate == null
                || candidate.getBasicConstraints() < 0
                || !certificate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
            return false;
        }
        try {
            certificate.verify(candidate.getPublicKey());
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    private static void requireSameSubject(X509Certificate certificate, ScepRequest request) {
        try {
            X500Principal requestedSubject = new X500Principal(
                    request.csr().getSubject().getEncoded());
            if (!certificate.getSubjectX500Principal().equals(requestedSubject)) {
                throw new ChallengeValidationException(
                        "renewal CSR subject does not match the presented certificate");
            }
        } catch (ChallengeValidationException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ChallengeValidationException("renewal CSR subject is invalid");
        }
    }

    private static void requireNoNewSubjectAlternativeNames(X509Certificate certificate,
                                                             ScepRequest request) {
        try {
            Set<String> priorNames = certificateSubjectAlternativeNames(certificate);
            Set<String> requestedNames = csrSubjectAlternativeNames(request);
            // A client may omit CA-added SANs, but it cannot add or change an identity on renewal.
            if (!priorNames.containsAll(requestedNames)) {
                throw new ChallengeValidationException(
                        "renewal CSR requests a subject alternative name absent from the presented certificate");
            }
        } catch (ChallengeValidationException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new ChallengeValidationException("renewal subject alternative names are invalid");
        }
    }

    private static Set<String> certificateSubjectAlternativeNames(X509Certificate certificate)
            throws Exception {
        org.bouncycastle.asn1.x509.Extension extension = new JcaX509CertificateHolder(certificate)
                .getExtension(Extension.subjectAlternativeName);
        return extension == null ? Set.of() : encodedNames(GeneralNames.getInstance(extension.getParsedValue()));
    }

    private static Set<String> csrSubjectAlternativeNames(ScepRequest request) throws Exception {
        Set<String> names = new HashSet<>();
        Attribute[] extensionRequests = request.csr().getAttributes(
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attribute : extensionRequests) {
            for (int index = 0; index < attribute.getAttrValues().size(); index++) {
                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(index));
                org.bouncycastle.asn1.x509.Extension san =
                        extensions.getExtension(Extension.subjectAlternativeName);
                if (san != null) {
                    names.addAll(encodedNames(GeneralNames.getInstance(san.getParsedValue())));
                }
            }
        }
        return names;
    }

    private static Set<String> encodedNames(GeneralNames generalNames) throws Exception {
        Set<String> names = new HashSet<>();
        for (GeneralName generalName : generalNames.getNames()) {
            names.add(Base64.getEncoder().encodeToString(
                    generalName.getEncoded(ASN1Encoding.DER)));
        }
        return names;
    }
}

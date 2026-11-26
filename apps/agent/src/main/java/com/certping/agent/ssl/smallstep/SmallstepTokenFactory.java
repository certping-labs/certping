// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.exception.PermanentAgentException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.MessageDigest;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

final class SmallstepTokenFactory {
    private SmallstepTokenFactory() {}

    static String create(SmallstepCredentials credentials, PKCS10CertificationRequest csr, Clock clock) {
        try {
            JWK jwk = JWK.parse(credentials.provisionerPrivateJwk());
            Signer signer = signer(jwk);
            Instant now = clock.instant();
            String subject = subject(csr);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(credentials.provisionerName()).subject(subject)
                    .audience(credentials.baseUrl() + "/1.0/sign")
                    .issueTime(Date.from(now)).notBeforeTime(Date.from(now.minusSeconds(5)))
                    .expirationTime(Date.from(now.plusSeconds(300))).jwtID(UUID.randomUUID().toString())
                    .claim("sans", sans(csr, subject))
                    .claim("sha", HexFormat.of().formatHex(
                            MessageDigest.getInstance("SHA-256").digest(csr.getEncoded())))
                    .build();
            return sign(jwk, signer, claims);
        } catch (PermanentAgentException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_TOKEN_FAILED",
                    "Could not create a Smallstep provisioner token", exception);
        }
    }

    static String createRevocation(SmallstepCredentials credentials, String serial, Clock clock) {
        try {
            JWK jwk = JWK.parse(credentials.provisionerPrivateJwk());
            Signer signer = signer(jwk);
            Instant now = clock.instant();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(credentials.provisionerName()).subject(serial)
                    .audience(credentials.baseUrl() + "/1.0/revoke")
                    .issueTime(Date.from(now)).notBeforeTime(Date.from(now.minusSeconds(5)))
                    .expirationTime(Date.from(now.plusSeconds(300))).jwtID(UUID.randomUUID().toString())
                    .build();
            return sign(jwk, signer, claims);
        } catch (PermanentAgentException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_TOKEN_FAILED",
                    "Could not create a Smallstep revocation token", exception);
        }
    }

    private static String sign(JWK jwk, Signer signer, JWTClaimsSet claims) throws Exception {
        String kid = jwk.getKeyID() == null ? jwk.computeThumbprint().toString() : jwk.getKeyID();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(signer.algorithm()).keyID(kid).build(), claims);
        jwt.sign(signer.signer());
        return jwt.serialize();
    }

    private static Signer signer(JWK jwk) throws Exception {
        if (jwk instanceof ECKey ec && ec.isPrivate()) {
            JWSAlgorithm algorithm = Curve.P_256.equals(ec.getCurve()) ? JWSAlgorithm.ES256
                    : Curve.P_384.equals(ec.getCurve()) ? JWSAlgorithm.ES384
                    : Curve.P_521.equals(ec.getCurve()) ? JWSAlgorithm.ES512 : null;
            if (algorithm == null) throw new PermanentAgentException("SMALLSTEP_JWK_UNSUPPORTED",
                    "Only P-256, P-384, and P-521 EC provisioner keys are supported");
            return new Signer(algorithm, new ECDSASigner(ec));
        }
        if (jwk instanceof RSAKey rsa && rsa.isPrivate()) {
            return new Signer(JWSAlgorithm.RS256, new RSASSASigner(rsa));
        }
        throw new PermanentAgentException("SMALLSTEP_JWK_UNSUPPORTED",
                "Smallstep provisioner JWK must contain an EC or RSA private key");
    }

    private static String subject(PKCS10CertificationRequest csr) {
        var rdns = csr.getSubject().getRDNs(BCStyle.CN);
        if (rdns.length == 0 || rdns[0].getFirst() == null) {
            throw new PermanentAgentException("SMALLSTEP_CSR_SUBJECT_MISSING",
                    "Smallstep JWK signing requires a CSR common name");
        }
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    private static List<String> sans(PKCS10CertificationRequest csr, String subject) throws Exception {
        List<String> names = new ArrayList<>();
        var attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes.length > 0 && attributes[0].getAttrValues().size() > 0) {
            Extensions extensions = Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
            Extension san = extensions.getExtension(Extension.subjectAlternativeName);
            if (san != null) {
                for (GeneralName name : GeneralNames.getInstance(san.getParsedValue()).getNames()) {
                    if (name.getTagNo() == GeneralName.dNSName
                            || name.getTagNo() == GeneralName.rfc822Name
                            || name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        names.add(DERIA5String.getInstance(name.getName()).getString());
                    } else if (name.getTagNo() == GeneralName.iPAddress) {
                        names.add(InetAddress.getByAddress(
                                ASN1OctetString.getInstance(name.getName()).getOctets()).getHostAddress());
                    }
                }
            }
        }
        if (names.isEmpty()) names.add(subject);
        return names;
    }

    private record Signer(JWSAlgorithm algorithm, JWSSigner signer) {}
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.scep.ca.ScepCaBackend;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScepRenewalAuthenticatorTest {

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void permitsOmittingPriorSansButRejectsAddingANewIdentity() throws Exception {
        KeyPair caKeys = rsa();
        X509Certificate caCertificate = certificate(
                caKeys.getPublic(), "CN=Renewal CA", "CN=Renewal CA", caKeys.getPrivate(), null, true);
        KeyPair priorKeys = rsa();
        GeneralNames priorSans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "device.corp.example"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "urn:device:42")
        });
        X509Certificate priorCertificate = certificate(priorKeys.getPublic(), "CN=device",
                "CN=Renewal CA", caKeys.getPrivate(), priorSans, false);
        ResolvedEndpoint endpoint = endpoint(caCertificate);

        ScepRequest subsetRequest = request(priorCertificate,
                csr(priorKeys, "CN=device", new GeneralNames(
                        new GeneralName(GeneralName.dNSName, "device.corp.example"))));
        assertThat(ScepRenewalAuthenticator.authenticate(endpoint, subsetRequest))
                .isSameAs(priorCertificate);

        ScepRequest expandedRequest = request(priorCertificate,
                csr(priorKeys, "CN=device", new GeneralNames(new GeneralName[]{
                        new GeneralName(GeneralName.dNSName, "device.corp.example"),
                        new GeneralName(GeneralName.dNSName, "other.corp.example")
                })));
        assertThatThrownBy(() -> ScepRenewalAuthenticator.authenticate(endpoint, expandedRequest))
                .isInstanceOf(ChallengeValidationException.class)
                .hasMessageContaining("absent from the presented certificate");
    }

    @Test
    void rejectsExpiredPriorCertificate() throws Exception {
        KeyPair caKeys = rsa();
        X509Certificate caCertificate = certificate(
                caKeys.getPublic(), "CN=Renewal CA", "CN=Renewal CA", caKeys.getPrivate(), null, true);
        KeyPair priorKeys = rsa();
        Instant now = Instant.now();
        X509Certificate expiredCertificate = certificate(priorKeys.getPublic(), "CN=device",
                "CN=Renewal CA", caKeys.getPrivate(), null, false,
                now.minus(Duration.ofDays(2)), now.minus(Duration.ofDays(1)));

        ScepRequest request = request(expiredCertificate, csr(priorKeys, "CN=device", null));

        assertThatThrownBy(() -> ScepRenewalAuthenticator.authenticate(
                endpoint(caCertificate), request))
                .isInstanceOf(ChallengeValidationException.class)
                .hasMessageContaining("expired or not yet valid");
    }

    private static ResolvedEndpoint endpoint(X509Certificate caCertificate) {
        ScepCaBackend backend = mock(ScepCaBackend.class);
        when(backend.getCaChain()).thenReturn(List.of(caCertificate));
        return new ResolvedEndpoint("endpoint", "42", "endpoint",
                com.certping.agent.model.enums.DevicePlatformType.INTUNE, List.of(), backend);
    }

    private static ScepRequest request(X509Certificate certificate, PKCS10CertificationRequest csr)
            throws Exception {
        byte[] encoded = csr.getEncoded();
        return new ScepRequest(ScepConstants.MSG_RENEWAL_REQ, "tx", new byte[16], csr,
                encoded, certificate, null);
    }

    private static PKCS10CertificationRequest csr(KeyPair keys, String subject, GeneralNames sans)
            throws Exception {
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(subject), keys.getPublic());
        if (sans != null) {
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.subjectAlternativeName, false, sans);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        }
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(keys.getPrivate()));
    }

    private static X509Certificate certificate(java.security.PublicKey publicKey, String subject,
                                               String issuer, PrivateKey issuerKey,
                                               GeneralNames sans, boolean isCa) throws Exception {
        Instant now = Instant.now();
        return certificate(publicKey, subject, issuer, issuerKey, sans, isCa,
                now.minus(Duration.ofMinutes(5)), now.plus(Duration.ofDays(1)));
    }

    private static X509Certificate certificate(java.security.PublicKey publicKey, String subject,
                                               String issuer, PrivateKey issuerKey,
                                               GeneralNames sans, boolean isCa,
                                               Instant notBefore, Instant notAfter) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), BigInteger.valueOf(Instant.now().toEpochMilli()),
                Date.from(notBefore), Date.from(notAfter),
                new X500Name(subject), publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (sans != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(issuerKey);
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.ejbca.EjbcaSignResult;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EjbcaScepCaBackendTest {

    private static final String HANDLE = "kv://ra";

    private EjbcaSigningService ejbca;
    private com.certping.agent.ssl.ejbca.EjbcaRevocationService revocationService;
    private EjbcaScepCaBackend backend;
    private X509Certificate leaf;
    private X509Certificate caCert;

    @BeforeAll
    static void provider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        ejbca = mock(EjbcaSigningService.class);
        SecretStore secretStore = mock(SecretStore.class);
        when(secretStore.read(HANDLE)).thenReturn(raSecretJson());

        AgentProperties props = new AgentProperties();
        props.getScep().getCa().setRaKeystoreHandle(HANDLE);

        KeyPair caKeys = rsa();
        caCert = selfSigned(caKeys, "CN=Test CA", true);
        leaf = selfSigned(rsa(), "CN=device-x", false);

        revocationService = org.mockito.Mockito.mock(
                com.certping.agent.ssl.ejbca.EjbcaRevocationService.class);
        backend = new EjbcaScepCaBackend(ejbca,
                revocationService,
                secretStore, props, JsonMapper.builderWithJackson2Defaults().build());
        backend.loadRa();
    }

    @Test
    void signReturnsLeafChainAndBackendIdentifiers() throws Exception {
        when(ejbca.sign(any(), isNull())).thenReturn(
                new EjbcaSignResult("leafPem", List.of(toPem(caCert)), "full", "01", "device-ee", leaf));

        IssuedCertificate issued = backend.sign(csr(), null);

        assertThat(issued.chain()).hasSize(2);
        assertThat(issued.leaf()).isEqualTo(leaf);
        assertThat(issued.chain().get(1).getSubjectX500Principal().getName()).contains("Test CA");
        assertThat(issued.endEntityName()).isEqualTo("device-ee");
        assertThat(issued.caProvider()).isEqualTo(CaProvider.EJBCA);
    }

    @Test
    void ejbcaRejectionBecomesCaException() {
        when(ejbca.sign(any(), isNull()))
                .thenThrow(new PermanentAgentException("EJBCA_REQUEST_REJECTED", "profile rejected key size"));

        assertThatThrownBy(() -> backend.sign(csr(), null))
                .isInstanceOf(CaException.class)
                .hasMessageContaining("profile rejected");
    }

    @Test
    void revokedCertificateIsRejectedBeforeRenewalSigning() {
        X509Certificate prior = mock(X509Certificate.class);
        when(prior.getIssuerX500Principal()).thenReturn(new javax.security.auth.x500.X500Principal("CN=Issuer"));
        when(prior.getSerialNumber()).thenReturn(java.math.BigInteger.valueOf(171));
        when(revocationService.status("CN=Issuer", "ab")).thenReturn(
                new com.certping.agent.ssl.ejbca.EjbcaRevocationService.Status(
                        true, "KEY_COMPROMISE", "2026-09-01T00:00:00Z"));

        assertThatThrownBy(() -> backend.assertRenewalAllowed(prior))
                .isInstanceOf(CaException.class)
                .hasMessageContaining("presented for renewal is revoked");
    }

    @Test
    void exposesLoadedRaIdentity() {
        assertThat(backend.getRaCertificate().getSubjectX500Principal().getName()).contains("CertPing RA");
        assertThat(backend.getRaPrivateKey()).isNotNull();
        // getCaChain publishes the ISSUER, not the RA leaf that heads the PKCS#12 chain.
        assertThat(backend.getCaChain()).hasSize(1);
        assertThat(backend.getCaChain().get(0).getSubjectX500Principal().getName()).contains("RA Issuer CA");
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static PKCS10CertificationRequest csr() throws Exception {
        KeyPair kp = rsa();
        return new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=device-x"), kp.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate()));
    }

    private static String raSecretJson() throws Exception {
        KeyPair caKp = rsa();
        X509Certificate caCert = selfSigned(caKp, "CN=RA Issuer CA", true);
        KeyPair raKp = rsa();
        X509Certificate raCert = issuedBy("CN=CertPing RA", raKp.getPublic(), caCert, caKp.getPrivate());
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        // PKCS#12 chain is leaf-first: [RA, CA] — caChain() must strip the RA leaf.
        ks.setKeyEntry("ra", raKp.getPrivate(), "pw".toCharArray(), new Certificate[]{raCert, caCert});
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ks.store(bos, "pw".toCharArray());
        return "{\"p12\":\"" + Base64.getEncoder().encodeToString(bos.toByteArray()) + "\",\"password\":\"pw\"}";
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            w.writeObject(cert);
        }
        return sw.toString();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static X509Certificate issuedBy(String subjectDn, PublicKey subjectKey,
                                            X509Certificate issuer, PrivateKey issuerKey) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new JcaX509CertificateHolder(issuer).getSubject(), BigInteger.valueOf(now.toEpochMilli() + 1),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                new X500Name(subjectDn), subjectKey);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }

    private static X509Certificate selfSigned(KeyPair keys, String dn, boolean ca) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(dn), BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                new X500Name(dn), keys.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }
}

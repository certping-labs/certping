// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.deployment.adapter.akamai.AkamaiCpsIssuanceService;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.model.message.SanDomainEntry;
import com.certping.agent.service.CredentialAccessService;
import com.certping.agent.ssl.acme.LetsEncryptAcmeService;
import com.certping.agent.ssl.digicert.DigiCertIssuanceService;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderFactory;
import com.certping.agent.ssl.globalsign.GlobalSignIssuanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SslIssuanceServiceTest {

    @Mock LetsEncryptAcmeService leService;
    @Mock DigiCertIssuanceService digicertService;
    @Mock GlobalSignIssuanceService globalSignService;
    @Mock AkamaiCpsIssuanceService akamaiCpsIssuanceService;
    @Mock CredentialAccessService credentialAccessService;
    @Mock DnsProviderFactory dnsProviderFactory;
    @Mock DnsProvider mockDnsProvider;

    private SslIssuanceService service;

    private static final IssuanceResult FAKE_RESULT = new IssuanceResult(
            "https://kv.vault.azure.net/secrets/cert-xref1", null, null,
            "AABBCC", "AA:BB:CC",
            OffsetDateTime.now(), OffsetDateTime.now().plusDays(90), "Let's Encrypt", null,
            "SHA256withRSA", null, null, null, "RSA", 2048, null, null, null, null, null, CertType.DV);

    @BeforeEach
    void setUp() {
        service = new SslIssuanceService(leService, digicertService, globalSignService,
                akamaiCpsIssuanceService, credentialAccessService, dnsProviderFactory);

        when(credentialAccessService.readSecret(anyString())).thenReturn("plain-api-token");
        when(dnsProviderFactory.create(anyString(), anyString())).thenReturn(mockDnsProvider);
    }

    @Test
    void issue_letsEncrypt_routesToLeService() {
        CertIssuanceMessage msg = buildMessage(CaProvider.LETS_ENCRYPT);
        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(FAKE_RESULT);

        IssuanceResult result = service.issue(msg);

        assertThat(result).isEqualTo(FAKE_RESULT);
        verify(leService).issue(eq("organization-1"), eq("xref-1"), eq("example.com"), eq(false),
                eq(Collections.emptyList()), eq(mockDnsProvider), anyMap(),
                isNull(String.class),
                isNull(Integer.class),
                isNull(com.certping.agent.exception.IssuanceCheckpoint.class), isNull(), eq(false), any());
    }

    @Test
    void issue_digicert_routesToDigiCertService() {
        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        msg.setCaCredentialHandle("https://kv.vault.azure.net/secrets/dc-key");
        when(digicertService.issue(anyString(), anyString(), any(), any(), any(), anyString(), any(), any(), any()))
                .thenReturn(FAKE_RESULT);

        IssuanceResult result = service.issue(msg);

        assertThat(result).isEqualTo(FAKE_RESULT);
        verify(digicertService).issue(eq("xref-1"), eq("example.com"),
                eq(Collections.emptyList()), eq(mockDnsProvider), anyMap(),
                eq("https://kv.vault.azure.net/secrets/dc-key"),
                isNull(Integer.class),
                isNull(com.certping.agent.exception.IssuanceCheckpoint.class), any());
    }

    @Test
    void issue_withSanDomainEntries_flattensPatternsAndBuildsProviders() {
        CertIssuanceMessage msg = buildMessage(CaProvider.LETS_ENCRYPT);
        SanDomainEntry entry = new SanDomainEntry();
        entry.setDnsProvider("CLOUDFLARE");
        entry.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/san-cred");
        entry.setPatterns(List.of("www.example.com", "api.example.com"));
        msg.setSanDomainEntries(List.of(entry));

        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(FAKE_RESULT);

        service.issue(msg);

        verify(leService).issue(anyString(), anyString(), anyString(), anyBoolean(),
                argThat(list -> list.contains("www.example.com") && list.contains("api.example.com")),
                any(), anyMap(), any(), any(), any(), isNull(), eq(false), any());
        verify(credentialAccessService, times(2)).readSecret(anyString());
    }

    @Test
    void issue_nullSanEntries_usesEmptyCollections() {
        CertIssuanceMessage msg = buildMessage(CaProvider.LETS_ENCRYPT);
        msg.setSanDomainEntries(null);
        when(leService.issue(anyString(), anyString(), anyString(), eq(false), eq(Collections.emptyList()), any(), eq(Collections.emptyMap()), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(FAKE_RESULT);

        IssuanceResult result = service.issue(msg);

        assertThat(result).isNotNull();
        verify(credentialAccessService, times(1)).readSecret(anyString());
    }

    @Test
    void issue_credentialReadFails_propagatesException() {
        when(credentialAccessService.readSecret(anyString()))
                .thenThrow(new PermanentAgentException("KV_SECRET_NOT_FOUND", "not found"));

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.LETS_ENCRYPT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_SECRET_NOT_FOUND"));
    }

    // ── Additional coverage: GLOBALSIGN, AKAMAI_CPS, default branch, SAN entry edge cases ─

    @Test
    void issue_globalsign_routesToGlobalSignService() {
        CertIssuanceMessage msg = buildMessage(CaProvider.GLOBALSIGN);
        when(globalSignService.issue(anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(FAKE_RESULT);

        IssuanceResult result = service.issue(msg);

        assertThat(result).isEqualTo(FAKE_RESULT);
        verify(globalSignService).issue(eq("xref-1"), eq("example.com"), eq(false),
                eq(Collections.emptyList()), eq(mockDnsProvider), anyMap(),
                isNull(Integer.class),
                isNull(com.certping.agent.exception.IssuanceCheckpoint.class), eq(false), any());
    }

    @Test
    void issue_customerHeldKey_issuesFromTheCustomersCsrWithTheAttemptsCheckpoint() {
        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        msg.setKeyCustody("CUSTOMER_HELD");
        msg.setCsrPem("-----BEGIN CERTIFICATE REQUEST-----\nABC\n-----END CERTIFICATE REQUEST-----");
        msg.setCaCredentialHandle("https://kv.vault.azure.net/secrets/dc-key");
        com.certping.agent.exception.IssuanceCheckpoint checkpoint = new com.certping.agent.exception.IssuanceCheckpoint(
                "DIGICERT", com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_FINALIZED, "9001", null, null);
        msg.setCheckpoint(checkpoint);
        when(digicertService.issueWithExternalCsr(anyString(), anyString(), anyList(), any(), anyMap(), anyString(),
                anyString(), any(), any(), any())).thenReturn(FAKE_RESULT);

        IssuanceResult result = service.issue(msg);

        assertThat(result).isEqualTo(FAKE_RESULT);
        verify(digicertService).issueWithExternalCsr(eq("xref-1"), eq("example.com"), eq(Collections.emptyList()),
                eq(mockDnsProvider), anyMap(), eq("https://kv.vault.azure.net/secrets/dc-key"), eq(msg.getCsrPem()),
                isNull(Integer.class), eq(checkpoint), eq(msg.getCheckpointRecorder()));
        verify(digicertService, never()).issue(anyString(), anyString(), anyList(), any(), anyMap(), anyString(), any(),
                any(), any());
    }

    @Test
    void issue_customerHeldKeyWithoutACsr_isRefusedForGood() {
        CertIssuanceMessage msg = buildMessage(CaProvider.GLOBALSIGN);
        msg.setKeyCustody("CUSTOMER_HELD");

        assertThatThrownBy(() -> service.issue(msg))
                .isInstanceOfSatisfying(com.certping.agent.exception.PermanentAgentException.class,
                        e -> assertThat(e.getErrorCode()).isEqualTo("CSR_MISSING"));
        verifyNoInteractions(digicertService, leService, globalSignService);
    }

    @Test
    void issue_akamaiCps_routesToAkamaiService_short_circuit() {
        CertIssuanceMessage msg = buildMessage(CaProvider.LETS_ENCRYPT);
        msg.setSpecialCertType("AKAMAI_CPS");
        when(akamaiCpsIssuanceService.issue(any())).thenReturn(FAKE_RESULT);

        IssuanceResult result = service.issue(msg);

        assertThat(result).isEqualTo(FAKE_RESULT);
        verify(akamaiCpsIssuanceService).issue(msg);
        verifyNoInteractions(leService, digicertService, globalSignService);
        verify(credentialAccessService, never()).readSecret(anyString());
    }

    @Test
    void issue_sanEntryWithNullPatterns_isSkippedInProviderMap() {
        CertIssuanceMessage msg = buildMessage(CaProvider.LETS_ENCRYPT);
        SanDomainEntry e1 = new SanDomainEntry();
        e1.setDnsProvider("CLOUDFLARE");
        e1.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/cred-a");
        e1.setPatterns(null); // null patterns
        SanDomainEntry e2 = new SanDomainEntry();
        e2.setDnsProvider("ROUTE53");
        e2.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/cred-b");
        e2.setPatterns(java.util.Arrays.asList("a.example.com", null, "", "  ", "b.example.com"));
        msg.setSanDomainEntries(List.of(e1, e2));

        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(FAKE_RESULT);

        service.issue(msg);

        // Both SAN credentials read, both providers created, but only 2 patterns in map
        verify(credentialAccessService, times(3)).readSecret(anyString()); // root + 2 san
        verify(dnsProviderFactory, times(3)).create(anyString(), anyString());
    }

    // ── Tests for CertificateMetadataExtractor (in same package; raises pkg coverage) ─

    @Test
    void certificateMetadataExtractor_nullCert_returnsBlankRecord() {
        CertificateMetadata md = CertificateMetadataExtractor.fromLeaf(null);
        assertThat(md.signatureAlgorithm()).isNull();
        assertThat(md.subjectDn()).isNull();
        assertThat(md.commonName()).isNull();
        assertThat(md.publicKeyAlgorithm()).isNull();
        assertThat(md.keySize()).isNull();
        assertThat(md.publicKeyCurve()).isNull();
        assertThat(md.keyUsage()).isNull();
        assertThat(md.extendedKeyUsage()).isNull();
        assertThat(md.subjectKeyIdentifier()).isNull();
        assertThat(md.authorityKeyIdentifier()).isNull();
        assertThat(md.signatureAlgorithmOid()).isNull();
    }

    @Test
    void certificateMetadataExtractor_nullCert_individualGettersReturnNull() {
        assertThat(CertificateMetadataExtractor.getSignatureAlgorithmOid(null)).isNull();
        assertThat(CertificateMetadataExtractor.getSubjectDn(null)).isNull();
        assertThat(CertificateMetadataExtractor.getCommonName(null)).isNull();
        assertThat(CertificateMetadataExtractor.getKeyUsage(null)).isNull();
        assertThat(CertificateMetadataExtractor.getPublicKeyCurve(null)).isNull();
        assertThat(CertificateMetadataExtractor.getExtendedKeyUsage(null)).isNull();
        assertThat(CertificateMetadataExtractor.getSubjectKeyIdentifier(null)).isNull();
        assertThat(CertificateMetadataExtractor.getAuthorityKeyIdentifier(null)).isNull();
    }

    @Test
    void certificateMetadataExtractor_realCert_extractsExpectedFields() throws Exception {
        java.security.cert.X509Certificate cert = buildSelfSignedForMeta();
        CertificateMetadata md = CertificateMetadataExtractor.fromLeaf(cert);
        assertThat(md.signatureAlgorithm()).contains("RSA");
        assertThat(md.signatureAlgorithmOid()).isNotBlank();
        assertThat(md.subjectDn()).contains("CN=meta.example.com");
        assertThat(md.commonName()).isEqualTo("meta.example.com");
        assertThat(md.publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(md.keySize()).isEqualTo(2048);
        assertThat(md.publicKeyCurve()).isNull(); // RSA, not EC
    }

    @Test
    void certificateMetadataExtractor_subjectDnWithNoCN_returnsNull() throws Exception {
        java.security.cert.X509Certificate cert = buildSelfSigned("O=Acme,C=US");
        assertThat(CertificateMetadataExtractor.getCommonName(cert)).isNull();
    }

    @Test
    void certificateMetadataExtractor_certWithExtensions_extractsKeyUsageEkuSkiAki() throws Exception {
        java.security.cert.X509Certificate cert = buildCertWithExtensions("CN=ext.example.com");
        CertificateMetadata md = CertificateMetadataExtractor.fromLeaf(cert);
        assertThat(md.keyUsage()).contains("digitalSignature");
        assertThat(md.keyUsage()).contains("keyEncipherment");
        assertThat(md.extendedKeyUsage()).isNotNull();
        assertThat(md.subjectKeyIdentifier()).isNotBlank();
        assertThat(md.authorityKeyIdentifier()).isNotBlank();
    }

    @Test
    void certificateMetadataExtractor_certWithAllKeyUsageBits_includesAll() throws Exception {
        // exercise bits 0..8 in formatKeyUsage
        java.security.cert.X509Certificate cert = buildCertWithAllKeyUsageBits("CN=allku.example.com");
        String ku = CertificateMetadataExtractor.getKeyUsage(cert);
        assertThat(ku).contains("digitalSignature");
        assertThat(ku).contains("nonRepudiation");
        assertThat(ku).contains("keyEncipherment");
        assertThat(ku).contains("dataEncipherment");
        assertThat(ku).contains("keyAgreement");
        assertThat(ku).contains("keyCertSign");
        assertThat(ku).contains("cRLSign");
    }

    @Test
    void certificateMetadataExtractor_certWithNoKeyUsageExtension_returnsNull() throws Exception {
        // The basic self-signed cert has no key usage extension at all
        java.security.cert.X509Certificate cert = buildSelfSigned("CN=plain.example.com");
        assertThat(CertificateMetadataExtractor.getKeyUsage(cert)).isNull();
        assertThat(CertificateMetadataExtractor.getExtendedKeyUsage(cert)).isNull();
        assertThat(CertificateMetadataExtractor.getSubjectKeyIdentifier(cert)).isNull();
        assertThat(CertificateMetadataExtractor.getAuthorityKeyIdentifier(cert)).isNull();
    }

    private static java.security.cert.X509Certificate buildCertWithExtensions(String dn) throws Exception {
        java.security.KeyPair kp = org.shredzone.acme4j.util.KeyPairUtils.createKeyPair(2048);
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                new javax.security.auth.x500.X500Principal(dn),
                java.math.BigInteger.valueOf(2L),
                new java.util.Date(),
                new java.util.Date(System.currentTimeMillis() + 86400000L),
                new javax.security.auth.x500.X500Principal(dn),
                kp.getPublic());
        // key usage: digitalSignature + keyEncipherment
        org.bouncycastle.asn1.x509.KeyUsage ku = new org.bouncycastle.asn1.x509.KeyUsage(
                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment);
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, ku);
        // extended key usage
        org.bouncycastle.asn1.x509.ExtendedKeyUsage eku = new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                new org.bouncycastle.asn1.x509.KeyPurposeId[] {
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth,
                        org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth
                });
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, eku);
        // SKI
        org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils u = new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils();
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                u.createSubjectKeyIdentifier(kp.getPublic()));
        // AKI
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                u.createAuthorityKeyIdentifier(kp.getPublic()));
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static java.security.cert.X509Certificate buildCertWithAllKeyUsageBits(String dn) throws Exception {
        java.security.KeyPair kp = org.shredzone.acme4j.util.KeyPairUtils.createKeyPair(2048);
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                new javax.security.auth.x500.X500Principal(dn),
                java.math.BigInteger.valueOf(3L),
                new java.util.Date(),
                new java.util.Date(System.currentTimeMillis() + 86400000L),
                new javax.security.auth.x500.X500Principal(dn),
                kp.getPublic());
        int all = org.bouncycastle.asn1.x509.KeyUsage.digitalSignature
                | org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation
                | org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment
                | org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment
                | org.bouncycastle.asn1.x509.KeyUsage.keyAgreement
                | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                | org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true,
                new org.bouncycastle.asn1.x509.KeyUsage(all));
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static java.security.cert.X509Certificate buildSelfSignedForMeta() throws Exception {
        return buildSelfSigned("CN=meta.example.com,O=Acme,C=US");
    }

    private static java.security.cert.X509Certificate buildSelfSigned(String dn) throws Exception {
        java.security.KeyPair kp = org.shredzone.acme4j.util.KeyPairUtils.createKeyPair(2048);
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                new javax.security.auth.x500.X500Principal(dn),
                java.math.BigInteger.valueOf(1L),
                new java.util.Date(),
                new java.util.Date(System.currentTimeMillis() + 86400000L),
                new javax.security.auth.x500.X500Principal(dn),
                kp.getPublic());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    // ── Tests for CsrKeyPairService (real implementation, in same package) ─

    @Test
    void csrKeyPairService_generateRsaKeyPair_returnsValidKey() {
        CsrKeyPairService svc = new CsrKeyPairService();
        java.security.KeyPair kp = svc.generateKeyPair();
        assertThat(kp).isNotNull();
        assertThat(kp.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void csrKeyPairService_generateKeyPairWithDefaults_returnsRsa() {
        CsrKeyPairService svc = new CsrKeyPairService();
        java.security.KeyPair kp = svc.generateKeyPair(null, null);
        assertThat(kp.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void csrKeyPairService_unsupportedKeyType_throws() {
        CsrKeyPairService svc = new CsrKeyPairService();
        assertThatThrownBy(() -> svc.generateKeyPair("DSA", 1024))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CSR_KEYTYPE_UNSUPPORTED"));
    }

    @Test
    void csrKeyPairService_unsupportedEcCurve_throws() {
        CsrKeyPairService svc = new CsrKeyPairService();
        assertThatThrownBy(() -> svc.generateKeyPair("ECDSA", 192))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CSR_EC_KEYSIZE_UNSUPPORTED"));
    }

    @Test
    void csrKeyPairService_generateCsrAndKeyPair_singleDomain_serializesPem() {
        CsrKeyPairService svc = new CsrKeyPairService();
        CsrKeyPairService.CsrKeyPairResult r = svc.generateCsrAndKeyPair("a.example.com", null);
        assertThat(r.csrPem()).contains("CERTIFICATE REQUEST");
        assertThat(r.privateKeyPem()).contains("PRIVATE KEY");
        assertThat(r.csrDer()).isNotEmpty();
    }

    @Test
    void csrKeyPairService_generateCsrAndKeyPair_withSans_includesAll() {
        CsrKeyPairService svc = new CsrKeyPairService();
        CsrKeyPairService.CsrKeyPairResult r =
                svc.generateCsrAndKeyPair("a.example.com", List.of("b.example.com"));
        assertThat(r.csrPem()).contains("CERTIFICATE REQUEST");
        assertThat(r.csrDer()).isNotEmpty();
    }

    @Test
    void csrKeyPairService_generateCsrAndKeyPair_policy_rsa() {
        CsrKeyPairService svc = new CsrKeyPairService();
        CsrKeyPairService.CsrKeyPairResult r =
                svc.generateCsrAndKeyPair("a.example.com", List.of(), "RSA", 2048);
        assertThat(r.csrPem()).isNotBlank();
        assertThat(r.privateKeyPem()).contains("PRIVATE KEY");
    }

    @Test
    void csrKeyPairService_buildCsr_emptyDomains_throws() {
        // CSRBuilder.sign with no domains should fail
        CsrKeyPairService svc = new CsrKeyPairService();
        java.security.KeyPair kp = svc.generateKeyPair();
        assertThatThrownBy(() -> svc.buildCsr(List.of(), kp))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CSR_BUILD_FAILED"));
    }

    private CertIssuanceMessage buildMessage(CaProvider ca) {
        CertIssuanceMessage msg = new CertIssuanceMessage();
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCaProvider(ca);
        msg.setDnsProvider("CLOUDFLARE");
        msg.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/dns-cred");
        return msg;
    }

    @Test
    void issue_customerHeldKeyWithoutCsr_isRefused() {
        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        msg.setKeyCustody("CUSTOMER_HELD");

        assertThatThrownBy(() -> service.issue(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode()).isEqualTo("CSR_MISSING"));
    }

    @Test
    void issue_customerHeldKey_sendsTheCustomersCsrToEachCa() {
        for (CaProvider ca : List.of(CaProvider.DIGICERT, CaProvider.LETS_ENCRYPT, CaProvider.GLOBALSIGN)) {
            CertIssuanceMessage msg = buildMessage(ca);
            msg.setKeyCustody("CUSTOMER_HELD");
            msg.setCsrPem("CSR-PEM");
            service.issue(msg);
        }

        verify(digicertService).issueWithExternalCsr(eq("xref-1"), eq("example.com"), anyList(),
                eq(mockDnsProvider), anyMap(), any(), eq("CSR-PEM"), any(), any(), any());
        verify(leService).issueWithExternalCsr(eq("organization-1"), eq("xref-1"), eq("example.com"), eq(false),
                anyList(), eq(mockDnsProvider), anyMap(), any(), eq("CSR-PEM"), anyBoolean(), any(), any());
        verify(globalSignService).issueWithExternalCsr(eq("xref-1"), eq("example.com"), eq(false), anyList(),
                eq(mockDnsProvider), anyMap(), eq("CSR-PEM"), any(), anyBoolean(), any(), any());
    }

}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.security.Permissions;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.access.AccessDeniedException;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;

import static com.certmanagement.service.cert.export.CertExportEligibilityPolicyTest.HANDLE;
import static com.certmanagement.service.cert.export.CertExportEligibilityPolicyTest.XREF;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.EC_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.RSA_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.agentBundle;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.chainFor;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.fingerprint;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.pem;
import static com.certmanagement.service.cert.export.KeyMaterialAssertions.assertNamedCurvePkcs8;
import static com.certmanagement.service.cert.export.KeyMaterialAssertions.assertSameKeyMaterial;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CertificateExportServiceTest {

    private static final long ORG_ID = 42L;
    private static final int USER_ID = 7;
    private static final Set<String> DEPLOYER = Set.of(Permissions.CERTIFICATE_READ, Permissions.CERTIFICATE_DEPLOY);
    private static final CertExportTestMaterial.Chain CHAIN = chainFor("*.example.com", RSA_LEAF_KEYS);
    private static final CertExportTestMaterial.Chain EC_CHAIN = chainFor("ec.example.com", EC_LEAF_KEYS);

    private final CertificateRepository certificateRepository = mock(CertificateRepository.class);
    private final AgentSecretStore store = mock(AgentSecretStore.class);
    private final CertExportRateLimiter rateLimiter = mock(CertExportRateLimiter.class);
    private final CertExportAuditRecorder auditRecorder = mock(CertExportAuditRecorder.class);
    private CertificateExportService service;
    private CertificateEntity cert;

    @BeforeEach
    void setUp() {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("agentSecretStore", store);
        CertExportEligibilityPolicy policy = new CertExportEligibilityPolicy(
                beans.getBeanProvider(AgentSecretStore.class), Clock.systemUTC());
        service = new CertificateExportService(certificateRepository, policy,
                beans.getBeanProvider(AgentSecretStore.class), rateLimiter, auditRecorder);

        cert = CertExportEligibilityPolicyTest.exportableCert();
        cert.setFingerprintSha256(fingerprint(CHAIN.leaf()));
        cert.setValidTo(OffsetDateTime.now().plusDays(30));
        when(certificateRepository.findByCertificateXrefAndOrganizationId(XREF, ORG_ID)).thenReturn(Optional.of(cert));
        when(store.isReady()).thenReturn(true);
        when(store.isAgentCertificateHandle(HANDLE, XREF)).thenReturn(true);
        when(store.read(HANDLE)).thenReturn(agentBundle(CHAIN, true));
        when(rateLimiter.tryAcquire(eq(USER_ID), any())).thenReturn(CertExportRateLimitDecision.ALLOWED);
    }

    @Test
    void exportsFullChain_auditsIt_andNamesTheFileAfterTheCommonName() {
        ExportedCertificateFile file = service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM"));

        assertThat(new String(file.content(), StandardCharsets.US_ASCII))
                .isEqualTo(pem(CHAIN.leaf()) + pem(CHAIN.intermediate()));
        assertThat(file.mediaType()).isEqualTo("application/x-pem-file");
        verify(auditRecorder).recordExport(any(), any());
    }

    @Test
    void certIsLookedUpInTheCallersOrgOnly_andAnotherOrgsCertIs404WithoutAVaultRead() {
        assertThatThrownBy(() -> service.export(99L, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                .isInstanceOf(ResourceNotFoundException.class);

        verify(certificateRepository).findByCertificateXrefAndOrganizationId(XREF, 99L);
        verify(store, never()).read(anyString());
        verify(auditRecorder).recordNotFound(99L, CertExportFormat.FULLCHAIN_PEM, XREF);
        verify(auditRecorder, never()).recordExport(any(), any());
    }

    @Test
    void handleNamingAnotherSecret_isRefusedBeforeAnyRead() {
        cert.setCertSecretHandle("https://kv-example.vault.azure.net/secrets/certping-org42-cred-1");

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getStatus().value()).isEqualTo(409);
                    assertThat(e.getReason()).isEqualTo("NOT_PLATFORM_STORED");
                });
        verify(store, never()).read(anyString());
    }

    @Test
    void fingerprintMismatch_is502AndAuditedAsARefusalOnly() {
        cert.setFingerprintSha256(fingerprint(chainFor("other.example.com", RSA_LEAF_KEYS).leaf()));

        assertExportFails("PRIVATE_KEY_PEM", 502, CertExportException.CERT_MATERIAL_MISMATCH);
        verify(auditRecorder).recordRefusal(ORG_ID, cert, CertExportFormat.PRIVATE_KEY_PEM,
                CertExportException.CERT_MATERIAL_MISMATCH);
        verify(auditRecorder, never()).recordExport(any(), any());
    }

    @Test
    void expiredCert_is410WithoutARead() {
        cert.setStatus("EXPIRED");

        assertExportFails("FULLCHAIN_PEM", 410, CertExportException.CERT_MATERIAL_GONE);
        verify(store, never()).read(anyString());
    }

    @Test
    void deletedSecret_is410() {
        when(store.read(HANDLE)).thenThrow(new ResourceNotFoundException("gone"));

        assertExportFails("FULLCHAIN_PEM", 410, CertExportException.CERT_MATERIAL_GONE);
    }

    @Test
    void destroyedDisabledOrDeletionScheduledSecret_is410() {
        when(store.read(HANDLE)).thenThrow(new AgentSecretGoneException("destroyed", null));

        assertExportFails("FULLCHAIN_PEM", 410, CertExportException.CERT_MATERIAL_GONE);
    }

    @Test
    void storeOutage_is503() {
        when(store.read(HANDLE)).thenThrow(new IllegalStateException("vault 500"));

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                .isInstanceOf(ServiceUnavailableException.class);
    }

    @Test
    void permissionDeniedOrThrottledRead_is503NotGone() {
        when(store.read(HANDLE)).thenThrow(new IllegalStateException("PERMISSION_DENIED"));

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("CERTIFICATE_PEM")))
                .isInstanceOf(ServiceUnavailableException.class);
    }

    @Test
    void keyFormatsOnAKeylessBundle_areKeyHeldExternally_butCertificatesStillExport() {
        when(store.read(HANDLE)).thenReturn(agentBundle(CHAIN, false));

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("PRIVATE_KEY_PEM")))
                .isInstanceOfSatisfying(CertExportException.class, e ->
                        assertThat(e.getReason()).isEqualTo("KEY_HELD_EXTERNALLY"));
        assertThat(service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("CERTIFICATE_PEM")).fileName())
                .isEqualTo("_wildcard.example.com-cert.pem");
    }

    @Test
    void rateLimited_is429BeforeAnyLookup() {
        when(rateLimiter.tryAcquire(USER_ID, CertExportFormat.FULLCHAIN_PEM))
                .thenReturn(new CertExportRateLimitDecision.Limited(120, true));

        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getStatus().value()).isEqualTo(429);
                    assertThat(e.getRetryAfterSeconds()).isEqualTo(120L);
                });
        verifyNoInteractions(certificateRepository);
    }

    @Test
    void invalidRequest_is400BeforeRateLimitOrLookup() {
        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF,
                new CertExportRequest("PKCS12", "short", null)))
                .isInstanceOfSatisfying(CertExportException.class, e ->
                        assertThat(e.getCode()).isEqualTo(CertExportException.INVALID_EXPORT_REQUEST));
        verifyNoInteractions(rateLimiter, certificateRepository);
    }

    @Test
    void missingUser_isRefused() {
        assertThatThrownBy(() -> service.export(ORG_ID, null, DEPLOYER, XREF, request("FULLCHAIN_PEM")))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void pkcs12Export_servesAPfxNamedAfterTheCommonName() {
        ExportedCertificateFile file = service.export(ORG_ID, USER_ID, DEPLOYER, XREF,
                new CertExportRequest("PKCS12", "correct horse 9", false));

        assertThat(file.fileName()).isEqualTo("_wildcard.example.com.pfx");
        assertThat(file.mediaType()).isEqualTo("application/x-pkcs12");
        verify(auditRecorder).recordExport(any(), any());
    }

    /** The production symptom was this export answering 502 once BouncyCastle was registered first. */
    @AcrossSecurityProviderModes
    void ecPrivateKeyPem_exports() throws Exception {
        useEcCertificate();

        ExportedCertificateFile file = service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request("PRIVATE_KEY_PEM"));

        try (PEMParser parser = new PEMParser(new StringReader(new String(file.content(), StandardCharsets.US_ASCII)))) {
            PrivateKeyInfo key = (PrivateKeyInfo) parser.readObject();
            assertNamedCurvePkcs8(key.getEncoded(), SECObjectIdentifiers.secp256r1);
            assertSameKeyMaterial(KeyFactory.getInstance("EC", "SunEC")
                    .generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded())), EC_LEAF_KEYS.getPrivate());
        }
        verify(auditRecorder).recordExport(any(), any());
    }

    @AcrossSecurityProviderModes
    void ecPkcs12_exportsAPfxTheJdkLoadsWithKeyAndChain() throws Exception {
        useEcCertificate();

        ExportedCertificateFile file = service.export(ORG_ID, USER_ID, DEPLOYER, XREF,
                new CertExportRequest("PKCS12", "correct horse 9", false));

        JdkPkcs12Reader.Contents loaded =
                JdkPkcs12Reader.read(file.content(), "correct horse 9".toCharArray(), "ec.example.com");
        assertThat(file.fileName()).isEqualTo("ec.example.com.pfx");
        assertSameKeyMaterial(loaded.key(), EC_LEAF_KEYS.getPrivate());
        assertThat(loaded.chain()).containsExactly(EC_CHAIN.leaf(), EC_CHAIN.intermediate());
    }

    private void useEcCertificate() {
        cert.setFingerprintSha256(fingerprint(EC_CHAIN.leaf()));
        when(store.read(HANDLE)).thenReturn(agentBundle(EC_CHAIN, true));
    }

    private void assertExportFails(String format, int status, String code) {
        assertThatThrownBy(() -> service.export(ORG_ID, USER_ID, DEPLOYER, XREF, request(format)))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getStatus().value()).isEqualTo(status);
                    assertThat(e.getCode()).isEqualTo(code);
                });
    }

    private static CertExportRequest request(String format) {
        return new CertExportRequest(format, null, null);
    }
}

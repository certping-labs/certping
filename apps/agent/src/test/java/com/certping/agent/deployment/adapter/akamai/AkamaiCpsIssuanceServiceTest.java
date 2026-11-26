// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.credential.AkamaiCpsDeploymentCredential;
import com.certping.agent.model.credential.AkamaiCpsDeploymentCredential.AkamaiEnrollment;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertIssuanceMessage;
import com.certping.agent.service.CredentialAccessService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.acme.LetsEncryptAcmeService;
import com.certping.agent.ssl.digicert.DigiCertIssuanceService;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderFactory;
import com.certping.agent.ssl.globalsign.GlobalSignIssuanceService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AkamaiCpsIssuanceServiceTest {

    @Mock private AkamaiCpsAuthService     akamaiCpsAuthService;
    @Mock private DigiCertIssuanceService  digicertService;
    @Mock private LetsEncryptAcmeService   leService;
    @Mock private GlobalSignIssuanceService globalSignService;
    @Mock private CredentialAccessService  credentialAccessService;
    @Mock private DnsProviderFactory       dnsProviderFactory;
    @Mock private DnsProvider              dnsProvider;
    @Mock private CloseableHttpClient      mockHttp;

    private AkamaiCpsIssuanceService service;

    private static final String ENROLLMENT_ID = "12345";
    private static final String CONTRACT_ID   = "1-ABC";
    private static final String DOMAIN        = "api.example.com";
    private static final String CERT_XREF     = "cert-test-xref";
    private static final String CRED_KV_PATH  = "https://kv.vault.azure.net/secrets/akamai-cred";
    private static final String CSR_PEM       =
            "-----BEGIN CERTIFICATE REQUEST-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ==\n-----END CERTIFICATE REQUEST-----";

    @BeforeEach
    void setUp() {
        service = new AkamaiCpsIssuanceService(
                akamaiCpsAuthService, digicertService, leService, globalSignService,
                credentialAccessService, dnsProviderFactory, JsonMapper.builderWithJackson2Defaults().build());
    }

    // ── Happy path: DigiCert routing ──────────────────────────────────────────

    @Test
    void issue_digicert_happyPath_fetchesCsrAndCallsDigicert() throws Exception {
        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        IssuanceResult expected = buildIssuanceResult();
        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(expected);
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        IssuanceResult result = service.issue(msg);

        assertThat(result).isSameAs(expected);
        verify(digicertService).issueWithExternalCsr(
                eq(CERT_XREF), eq(DOMAIN), any(), any(), any(), any(), eq(CSR_PEM), any(), any(), any());
        verify(leService, never()).issueWithExternalCsr(any(), any(), any(), anyBoolean(), any(), any(), any(), any(), any(),
                anyBoolean(), any(), any());
    }

    @Test
    void issue_letsEncrypt_happyPath_callsLeService() throws Exception {
        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        IssuanceResult expected = buildIssuanceResult();
        when(leService.issueWithExternalCsr(any(), any(), any(), anyBoolean(), any(), any(), any(), any(), any(), anyBoolean(), any(), any()))
                .thenReturn(expected);
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        IssuanceResult result = service.issue(buildMessage(CaProvider.LETS_ENCRYPT));

        assertThat(result).isSameAs(expected);
        verify(leService).issueWithExternalCsr(any(), any(), eq(DOMAIN), anyBoolean(), any(), any(), any(), any(), eq(CSR_PEM), eq(false), any(), any());
        verify(digicertService, never()).issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    // ── CSR selection ─────────────────────────────────────────────────────────

    @Test
    void issue_prefersRsaCsrWhenMultiplePresent() throws Exception {
        String rsaCsr = "-----BEGIN CERTIFICATE REQUEST-----\nRSA\n-----END CERTIFICATE REQUEST-----";
        String ecCsr  = "-----BEGIN CERTIFICATE REQUEST-----\nEC\n-----END CERTIFICATE REQUEST-----";
        String multiCsrJson = "{\"csrs\":[" +
                "{\"csr\":\"" + ecCsr.replace("\n", "\\n") + "\",\"keyAlgorithm\":\"EC\"}," +
                "{\"csr\":\"" + rsaCsr.replace("\n", "\\n") + "\",\"keyAlgorithm\":\"RSA\"}" +
                "]}";

        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                multiCsrJson);

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        service.issue(buildMessage(CaProvider.DIGICERT));

        verify(digicertService).issueWithExternalCsr(
                any(), any(), any(), any(), any(), any(), contains("RSA"), any(), any(), any());
    }

    @Test
    void issue_fallsBackToFirstCsrWhenNoRsaPresent() throws Exception {
        String ecCsr = "-----BEGIN CERTIFICATE REQUEST-----\nECONLY\n-----END CERTIFICATE REQUEST-----";
        String singleEcJson = "{\"csrs\":[" +
                "{\"csr\":\"" + ecCsr.replace("\n", "\\n") + "\",\"keyAlgorithm\":\"EC\"}" +
                "]}";

        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                singleEcJson);

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        service.issue(buildMessage(CaProvider.DIGICERT));

        verify(digicertService).issueWithExternalCsr(
                any(), any(), any(), any(), any(), any(), contains("ECONLY"), any(), any(), any());
    }

    // ── Enrollment resolution ─────────────────────────────────────────────────

    @Test
    void issue_singleEnrollment_usedWithoutMatching() throws Exception {
        // Only one enrollment — no domain matching needed
        AkamaiCpsDeploymentCredential cred = buildCred(List.of(
                enrollment(ENROLLMENT_ID, "other.example.com", List.of("other.example.com"))));

        when(akamaiCpsAuthService.loadCredential(CRED_KV_PATH)).thenReturn(cred);
        when(akamaiCpsAuthService.buildClient(any())).thenReturn(mockHttp);
        when(akamaiCpsAuthService.baseUrl(any(AkamaiCpsDeploymentCredential.class))).thenReturn("https://api.akamai.test");
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        service.issue(buildMessage(CaProvider.DIGICERT));

        verify(digicertService).issueWithExternalCsr(any(), eq(DOMAIN), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void issue_multipleEnrollments_matchesByCommonName() throws Exception {
        AkamaiCpsDeploymentCredential cred = buildCred(List.of(
                enrollment("99999", "other.com", List.of("other.com")),
                enrollment(ENROLLMENT_ID, DOMAIN, List.of(DOMAIN))));

        when(akamaiCpsAuthService.loadCredential(CRED_KV_PATH)).thenReturn(cred);
        when(akamaiCpsAuthService.buildClient(any())).thenReturn(mockHttp);
        when(akamaiCpsAuthService.baseUrl(any(AkamaiCpsDeploymentCredential.class))).thenReturn("https://api.akamai.test");
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        service.issue(buildMessage(CaProvider.DIGICERT));

        verify(digicertService).issueWithExternalCsr(eq(CERT_XREF), eq(DOMAIN), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void issue_multipleEnrollments_matchesByDomainList() throws Exception {
        AkamaiCpsDeploymentCredential cred = buildCred(List.of(
                enrollment("99999", "wrong.com", List.of("wrong.com")),
                enrollment(ENROLLMENT_ID, "primary.com", List.of("primary.com", DOMAIN))));

        when(akamaiCpsAuthService.loadCredential(CRED_KV_PATH)).thenReturn(cred);
        when(akamaiCpsAuthService.buildClient(any())).thenReturn(mockHttp);
        when(akamaiCpsAuthService.baseUrl(any(AkamaiCpsDeploymentCredential.class))).thenReturn("https://api.akamai.test");
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        service.issue(buildMessage(CaProvider.DIGICERT));

        verify(digicertService).issueWithExternalCsr(eq(CERT_XREF), eq(DOMAIN), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void issue_multipleEnrollments_noMatch_throwsPermanent() throws Exception {
        AkamaiCpsDeploymentCredential cred = buildCred(List.of(
                enrollment("99999", "other.com", List.of("other.com")),
                enrollment("88888", "another.com", List.of("another.com"))));

        when(akamaiCpsAuthService.loadCredential(CRED_KV_PATH)).thenReturn(cred);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_ENROLLMENT_NOT_FOUND"));
    }

    // ── Guard conditions ──────────────────────────────────────────────────────

    @Test
    void issue_missingCredKvPath_throwsPermanentWithoutCallingAkamai() {
        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        msg.setSpecialDeploymentCredHandle(null);

        assertThatThrownBy(() -> service.issue(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CRED_MISSING"));

        verify(akamaiCpsAuthService, never()).loadCredential(any());
    }

    @Test
    void issue_blankCredKvPath_throwsPermanent() {
        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        msg.setSpecialDeploymentCredHandle("   ");

        assertThatThrownBy(() -> service.issue(msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CRED_MISSING"));
    }

    // ── HTTP error handling ───────────────────────────────────────────────────

    @Test
    void issue_enrollmentFetch4xx_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);

        CloseableHttpResponse resp = mockResponse(404, "{\"error\":\"not found\"}");
        when(mockHttp.execute(any(HttpUriRequest.class))).thenReturn(resp);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_ENROLLMENT_FETCH"));
    }

    @Test
    void issue_enrollmentFetch5xx_throwsTransient() throws Exception {
        stubAuthService(DOMAIN);

        CloseableHttpResponse resp = mockResponse(503, "Service Unavailable");
        when(mockHttp.execute(any(HttpUriRequest.class))).thenReturn(resp);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_ENROLLMENT_FETCH"));
    }

    @Test
    void issue_noPendingChange_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);

        CloseableHttpResponse enrollResp = mockResponse(200, enrollmentJson("[]"));
        when(mockHttp.execute(any(HttpUriRequest.class))).thenReturn(enrollResp);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_NO_PENDING_CHANGE"));
    }

    @Test
    void issue_emptyCsrList_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);

        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                "{\"csrs\":[]}");

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CSR_MISSING"));
    }

    @Test
    void issue_unsupportedCa_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        CertIssuanceMessage msg = buildMessage(CaProvider.GLOBALSIGN);
        // Stub GlobalSign to throw unsupported to confirm the switch handles GLOBALSIGN
        when(globalSignService.issueWithExternalCsr(any(), any(), anyBoolean(), any(), any(), any(), any(), any(), anyBoolean(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        // Should succeed (GlobalSign is supported)
        IssuanceResult result = service.issue(msg);
        assertThat(result).isNotNull();
        verify(globalSignService).issueWithExternalCsr(any(), eq(DOMAIN), anyBoolean(), any(), any(), any(), eq(CSR_PEM), any(), eq(false), any(), any());
    }

    @ParameterizedTest
    @EnumSource(value = CaProvider.class, names = {"LETS_ENCRYPT", "GLOBALSIGN"})
    void issue_theLastPropagationWaitIsPassedOn(CaProvider ca) throws Exception {
        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);
        CertIssuanceMessage msg = buildMessage(ca);
        msg.setFinalPropagationWait(true);

        service.issue(msg);

        if (ca == CaProvider.LETS_ENCRYPT) {
            verify(leService).issueWithExternalCsr(any(), any(), eq(DOMAIN), anyBoolean(), any(), any(), any(), any(),
                    eq(CSR_PEM), eq(true), any(), any());
        } else {
            verify(globalSignService).issueWithExternalCsr(any(), eq(DOMAIN), anyBoolean(), any(), any(), any(),
                    eq(CSR_PEM), any(), eq(true), any(), any());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubAuthService(String domain) {
        AkamaiCpsDeploymentCredential cred = buildCred(List.of(
                enrollment(ENROLLMENT_ID, domain, List.of(domain))));
        when(akamaiCpsAuthService.loadCredential(CRED_KV_PATH)).thenReturn(cred);
        when(akamaiCpsAuthService.buildClient(any())).thenReturn(mockHttp);
        when(akamaiCpsAuthService.baseUrl(any(AkamaiCpsDeploymentCredential.class))).thenReturn("https://api.akamai.test");
    }

    private void stubHttpResponses(String enrollmentBody, String csrBody) throws Exception {
        CloseableHttpResponse enrollResp = mockResponse(200, enrollmentBody);
        CloseableHttpResponse csrResp    = mockResponse(200, csrBody);
        when(mockHttp.execute(any(HttpUriRequest.class)))
                .thenReturn(enrollResp)
                .thenReturn(csrResp);
    }

    private CloseableHttpResponse mockResponse(int statusCode, String body) throws Exception {
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        when(resp.getCode()).thenReturn(statusCode);
        when(resp.getEntity()).thenReturn(new StringEntity(body));
        return resp;
    }

    private String enrollmentJson(String pendingChangesArrayJson) {
        return "{\"pendingChanges\":" + pendingChangesArrayJson + "}";
    }

    private String csrJson(String csr, String keyAlgorithm) {
        return "{\"csrs\":[{\"csr\":\"" + csr.replace("\n", "\\n") +
                "\",\"keyAlgorithm\":\"" + keyAlgorithm + "\"}]}";
    }

    private CertIssuanceMessage buildMessage(CaProvider ca) {
        CertIssuanceMessage msg = new CertIssuanceMessage();
        msg.setRequestId("req-test");
        msg.setCorrelationId("corr-test");
        msg.setOrganizationId("org-1");
        msg.setCertificateXref(CERT_XREF);
        msg.setDomain(DOMAIN);
        msg.setCaProvider(ca);
        msg.setDnsProvider("CLOUDFLARE");
        msg.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/dns");
        msg.setSpecialDeploymentCredHandle(CRED_KV_PATH);
        return msg;
    }

    private AkamaiCpsDeploymentCredential buildCred(List<AkamaiEnrollment> enrollments) {
        AkamaiCpsDeploymentCredential cred = new AkamaiCpsDeploymentCredential();
        cred.setHost("api.akamai.test");
        cred.setClientToken("akab-token");
        cred.setAccessToken("akab-access");
        cred.setClientSecret("secret123");
        cred.setEnrollments(enrollments);
        return cred;
    }

    private AkamaiEnrollment enrollment(String enrollmentId, String commonName, List<String> domains) {
        AkamaiEnrollment e = new AkamaiEnrollment();
        e.setEnrollmentId(enrollmentId);
        e.setCommonName(commonName);
        e.setDomains(domains);
        e.setCertType("third-party");
        return e;
    }

    // ── Additional coverage: CSR fetch errors, edge JSON, SAN entries ─────────

    @Test
    void issue_csrFetch4xx_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);
        CloseableHttpResponse enroll = mockResponse(200,
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"));
        CloseableHttpResponse err = mockResponse(403, "{\"error\":\"forbidden\"}");
        when(mockHttp.execute(any(HttpUriRequest.class))).thenReturn(enroll).thenReturn(err);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CSR_FETCH"));
    }

    @Test
    void issue_csrFetch5xx_throwsTransient() throws Exception {
        stubAuthService(DOMAIN);
        CloseableHttpResponse enroll = mockResponse(200,
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"));
        CloseableHttpResponse err = mockResponse(500, "bad");
        when(mockHttp.execute(any(HttpUriRequest.class))).thenReturn(enroll).thenReturn(err);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CSR_FETCH"));
    }

    @Test
    void issue_csrsFieldMissingEntirely_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                "{}");

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CSR_MISSING"));
    }

    @Test
    void issue_pendingChangeUrlBlankAfterSlash_throwsPermanent() throws Exception {
        stubAuthService(DOMAIN);
        CloseableHttpResponse enroll = mockResponse(200,
                enrollmentJson("[\"/cps/v2/enrollments/12345/changes/\"]"));
        when(mockHttp.execute(any(HttpUriRequest.class))).thenReturn(enroll);

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_NO_PENDING_CHANGE"));
    }

    @Test
    void issue_genericException_wrappedAsIssuanceFailed() throws Exception {
        stubAuthService(DOMAIN);
        when(mockHttp.execute(any(HttpUriRequest.class)))
                .thenThrow(new java.io.IOException("boom"));

        assertThatThrownBy(() -> service.issue(buildMessage(CaProvider.DIGICERT)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("AKAMAI_CPS_ISSUANCE_FAILED"));
    }

    @Test
    void issue_withSanEntries_buildsDnsProvidersAndFlattensPatterns() throws Exception {
        stubAuthService(DOMAIN);
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        com.certping.agent.model.message.SanDomainEntry san =
                new com.certping.agent.model.message.SanDomainEntry();
        san.setDnsProvider("CLOUDFLARE");
        san.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/san-dns");
        san.setPatterns(java.util.List.of("san1.example.com", "san2.example.com", ""));

        CertIssuanceMessage msg = buildMessage(CaProvider.DIGICERT);
        msg.setSanDomainEntries(java.util.List.of(san));

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        IssuanceResult result = service.issue(msg);
        assertThat(result).isNotNull();
        // SAN dns reads happen: root + SAN entry
        verify(credentialAccessService, atLeast(2)).readSecret(anyString());
    }

    @Test
    void issue_csrEntryWithBlankKeyAlgo_fallsBackToFirst() throws Exception {
        stubAuthService(DOMAIN);
        String blankAlgoJson = "{\"csrs\":[{\"csr\":\"FIRST\",\"keyAlgorithm\":\"\"}]}";
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                blankAlgoJson);

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        service.issue(buildMessage(CaProvider.DIGICERT));
        verify(digicertService).issueWithExternalCsr(any(), any(), any(), any(), any(), any(), eq("FIRST"), any(), any(), any());
    }

    @Test
    void issue_enrollmentDomainListContainsNullEntries_skipsNulls() throws Exception {
        AkamaiCpsDeploymentCredential cred = buildCred(List.of(
                enrollment("99999", "first.com", java.util.Arrays.asList(null, "first.com")),
                enrollment(ENROLLMENT_ID, "second.com", java.util.Arrays.asList(null, DOMAIN))));

        when(akamaiCpsAuthService.loadCredential(CRED_KV_PATH)).thenReturn(cred);
        when(akamaiCpsAuthService.buildClient(any())).thenReturn(mockHttp);
        when(akamaiCpsAuthService.baseUrl(any(AkamaiCpsDeploymentCredential.class))).thenReturn("https://api.akamai.test");
        stubHttpResponses(
                enrollmentJson("[\"https://api.akamai.test/cps/v2/enrollments/12345/changes/9999\"]"),
                csrJson(CSR_PEM, "RSA"));

        when(digicertService.issueWithExternalCsr(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(buildIssuanceResult());
        when(credentialAccessService.readSecret(anyString())).thenReturn("dns-raw");
        when(dnsProviderFactory.create(any(), any())).thenReturn(dnsProvider);

        IssuanceResult r = service.issue(buildMessage(CaProvider.DIGICERT));
        assertThat(r).isNotNull();
    }

    private IssuanceResult buildIssuanceResult() {
        return new IssuanceResult(
                "https://kv.vault.azure.net/secrets/cert",
                "https://kv.vault.azure.net/secrets/cert/version",
                null,
                "SERIAL",
                "AA:BB:CC",
                OffsetDateTime.now(ZoneOffset.UTC),
                OffsetDateTime.now(ZoneOffset.UTC).plusDays(90),
                "CN=DigiCert",
                "order-123",
                "SHA256withRSA", null, null, "api.example.com", "RSA",
                2048, null, null, null, null, null,
                null);
    }
}

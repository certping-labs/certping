// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.aspect.FeatureGatedAspect;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.exception.CertExportException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cert.export.CertificateExportService;
import com.certmanagement.service.cert.export.ExportedCertificateFile;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CertExportControllerTest {

    private static final long ORG_ID = 42L;

    private final CertificateExportService exportService = mock(CertificateExportService.class);
    private final CertExportController controller = new CertExportController(exportService);

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(7, String.valueOf(ORG_ID), "req-1", "user@example.com");
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void servesTheFileAsAnUncachedAttachment_passingTheCallersPermissionsWithoutRoles() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", null,
                "certificate:read", "certificate:deploy", "ROLE_CERT_MANAGER"));
        CertExportRequest request = new CertExportRequest("PKCS12", "correct horse 9", false);
        ExportedCertificateFile file = new ExportedCertificateFile(
                new byte[] {1, 2, 3}, "application/x-pkcs12", "_wildcard.example.com.pfx");
        when(exportService.export(ORG_ID, 7, Set.of("certificate:read", "certificate:deploy"), "cert-1", request))
                .thenReturn(file);

        ResponseEntity<byte[]> response = controller.export("cert-1", request);

        HttpHeaders headers = response.getHeaders();
        assertThat(response.getBody()).containsExactly(1, 2, 3);
        assertThat(headers.getContentType()).hasToString("application/x-pkcs12");
        assertThat(headers.getFirst(HttpHeaders.CONTENT_DISPOSITION))
                .isEqualTo("attachment; filename=\"_wildcard.example.com.pfx\"");
        assertThat(headers.getCacheControl()).isEqualTo("no-store");
        assertThat(headers.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
    }

    @Test
    void isRefusedWhenCertificateDownloadIsOff() {
        FeatureFlagService featureFlagService = mock(FeatureFlagService.class);
        doThrow(new FeatureDisabledException(FeatureFlags.CERTIFICATE_DOWNLOAD))
                .when(featureFlagService).assertEnabled(FeatureFlags.CERTIFICATE_DOWNLOAD, ORG_ID);
        AspectJProxyFactory factory = new AspectJProxyFactory(controller);
        factory.setProxyTargetClass(true);
        factory.addAspect(new FeatureGatedAspect(featureFlagService));
        CertExportController gated = factory.getProxy();

        assertThatThrownBy(() -> gated.export("cert-1", new CertExportRequest("FULLCHAIN_PEM", null, null)))
                .isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(exportService);
    }

    @Test
    @SuppressWarnings("unchecked")
    void exportErrors_renderTheEnvelopeWithCodeReasonAndRetryAfter() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build());
        MockHttpServletRequest http = new MockHttpServletRequest("POST", "/api/v1/certs/cert-1/export");

        ResponseEntity<Object> conflict = handler.handleCertExport(
                CertExportException.notExportable("NOT_PLATFORM_STORED", "This certificate cannot be exported."), http);
        ResponseEntity<Object> limited = handler.handleCertExport(CertExportException.rateLimited(90), http);
        ResponseEntity<Object> keyRefused = handler.handleCertExport(CertExportException.keyNotPermitted(), http);

        assertThat(conflict.getStatusCode().value()).isEqualTo(409);
        assertThat((Map<String, Object>) conflict.getBody())
                .containsEntry("code", "CERT_NOT_EXPORTABLE")
                .containsEntry("reason", "NOT_PLATFORM_STORED")
                .containsEntry("path", "/api/v1/certs/cert-1/export")
                .containsKeys("status", "error", "message", "timestamp");
        assertThat(limited.getStatusCode().value()).isEqualTo(429);
        assertThat(limited.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("90");
        assertThat((Map<String, Object>) limited.getBody())
                .containsEntry("code", "EXPORT_RATE_LIMITED").doesNotContainKey("reason");
        assertThat(keyRefused.getStatusCode().value()).isEqualTo(403);
        assertThat((Map<String, Object>) keyRefused.getBody())
                .containsEntry("code", "EXPORT_KEY_NOT_PERMITTED")
                .containsEntry("message", "You can download the certificate and chain, but not the private key.")
                .doesNotContainKey("reason");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"format\":\"PKCS12\",\"password\":\"Secret-pass-123\",\"legacyPkcs12\":\"yes\"}",
            "{\"format\":\"PKCS12\",\"password\":\"Secret-pass-123\",",
            "not json Secret-pass-123"})
    void unreadableBody_getsTheExportEnvelope_withAFixedMessageThatEchoesNothing(String body) throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                .build();

        String response = mvc.perform(post("/api/v1/certs/cert-1/export")
                        .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.code").value("INVALID_EXPORT_REQUEST"))
                .andExpect(jsonPath("$.message").value(CertExportController.UNREADABLE_BODY_MESSAGE))
                .andExpect(jsonPath("$.path").value("/api/v1/certs/cert-1/export"))
                .andExpect(jsonPath("$.timestamp").exists())
                .andExpect(jsonPath("$.reason").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        assertThat(JsonMapper.builderWithJackson2Defaults().build().readTree(response).propertyNames().iterator()).toIterable()
                .containsExactly("status", "error", "code", "message", "path", "timestamp");
        assertThat(response).doesNotContain("Secret-pass-123", "yes", "JSON parse error", "Cannot deserialize",
                "com.fasterxml", "CertExportRequest");
        verifyNoInteractions(exportService);
    }
}

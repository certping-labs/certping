// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.google.api.gax.longrunning.OperationFuture;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.ApiExceptionFactory;
import com.google.api.gax.rpc.PermissionDeniedException;
import com.google.api.gax.rpc.ResourceExhaustedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.api.gax.rpc.UnauthenticatedException;
import com.google.api.gax.rpc.UnavailableException;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.compute.v1.RegionSslCertificatesClient;
import com.google.cloud.compute.v1.RegionSslCertificatesSettings;
import com.google.cloud.compute.v1.SslCertificate;
import com.google.cloud.compute.v1.SslCertificatesClient;
import com.google.cloud.compute.v1.SslCertificatesSettings;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Coverage for {@link GcpComputeSslCertificateService} — happy-path create + delete, throttle/auth
 * arms, blank-input early returns, and the resource-name parser (canonical + partial + bogus shapes).
 */
class GcpComputeSslCertificateServiceThrottleTest {

    private static StatusCode statusCode(StatusCode.Code code, int transport) {
        return new StatusCode() {
            @Override public Code getCode() { return code; }
            @Override public Object getTransportCode() { return transport; }
        };
    }

    private static <T extends ApiException> T fakeApi(StatusCode.Code code, int t, Class<T> type) {
        StatusCode sc = statusCode(code, t);
        return type.cast(ApiExceptionFactory.createException(new RuntimeException(code.name()), sc, true));
    }

    private static CertificateBundle bundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
                null,
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----");
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static OperationFuture operationOf(Object result) throws Exception {
        OperationFuture f = mock(OperationFuture.class);
        org.mockito.Mockito.doReturn(result).when(f).get();
        return f;
    }

    // ===================== createSslCertificate =====================

    @Test
    void createSslCertificate_unavailable_throwsRetryableThrottle() {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        UnavailableException throttle = fakeApi(StatusCode.Code.UNAVAILABLE, 503, UnavailableException.class);
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenThrow(throttle);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void createSslCertificate_resourceExhausted_throwsRetryableThrottle() {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        ResourceExhaustedException re = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenThrow(re);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    // ===================== hard SSL-cert quota (permanent, not throttle) =====================

    @Test
    void isSslCertificateQuotaExceeded_matchesExplicitQuotaMarkers() {
        assertThat(GcpComputeSslCertificateService.isSslCertificateQuotaExceeded(
                new RuntimeException("Operation failed: QUOTA_EXCEEDED"))).isTrue();
        assertThat(GcpComputeSslCertificateService.isSslCertificateQuotaExceeded(
                new RuntimeException("metric SSL_CERTIFICATES exceeded LIMIT of 10"))).isTrue();
        // Nested cause carrying the marker.
        assertThat(GcpComputeSslCertificateService.isSslCertificateQuotaExceeded(
                new RuntimeException("wrapper", new RuntimeException("quotaExceeded ssl")))).isTrue();
    }

    @Test
    void isSslCertificateQuotaExceeded_ignoresBareResourceExhaustedAndForbidden() {
        // A bare RESOURCE_EXHAUSTED / 429 is a transient rate-limit, NOT a hard quota — must stay
        // retryable (handled by RateLimitClassifier), so this returns false.
        assertThat(GcpComputeSslCertificateService.isSslCertificateQuotaExceeded(
                new RuntimeException("RESOURCE_EXHAUSTED"))).isFalse();
        // GCP's masked case — a bare FORBIDDEN with no quota detail can't be identified.
        assertThat(GcpComputeSslCertificateService.isSslCertificateQuotaExceeded(
                new RuntimeException("Operation failed with status = PERMISSION_DENIED, message = FORBIDDEN")))
                .isFalse();
        assertThat(GcpComputeSslCertificateService.isSslCertificateQuotaExceeded(null)).isFalse();
    }

    @Test
    void createSslCertificate_hardQuota_throwsPermanentQuotaCode() {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        RuntimeException quota = new RuntimeException(
                "Operation failed: QUOTA_EXCEEDED, metric compute.googleapis.com/ssl_certificates, limit 10");
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenThrow(quota);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DEPLOY_GCP_QUOTA_EXCEEDED"));
        }
    }

    @Test
    void createSslCertificate_success_returnsSelfLink() throws Exception {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenReturn(op);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            String r = new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "my-cert", bundle(), mock(GoogleCredentials.class));
            assertThat(r).isEqualTo("https://www.googleapis.com/compute/v1/projects/proj/global/sslCertificates/my-cert");
        }
    }

    @Test
    void createSslCertificate_regionalLocation_insertsRegionalCert() throws Exception {
        RegionSslCertificatesClient mockClient = mock(RegionSslCertificatesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.insertAsync(anyString(), anyString(), any(SslCertificate.class))).thenReturn(op);
        try (MockedStatic<RegionSslCertificatesClient> s = mockStatic(RegionSslCertificatesClient.class);
             MockedStatic<SslCertificatesClient> global = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> RegionSslCertificatesClient.create(any(RegionSslCertificatesSettings.class))).thenReturn(mockClient);
            String r = new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "us-central1", "my-cert", bundle(), mock(GoogleCredentials.class));
            assertThat(r).isEqualTo(
                    "https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1/sslCertificates/my-cert");
            verify(mockClient).insertAsync(eq("proj"), eq("us-central1"), any(SslCertificate.class));
            global.verifyNoInteractions();
        }
    }

    @Test
    void createSslCertificate_unauthenticated_throwsPermanent() {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        UnauthenticatedException ue = fakeApi(StatusCode.Code.UNAUTHENTICATED, 401, UnauthenticatedException.class);
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenThrow(ue);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_SSL_CERT_FAILED");
        }
    }

    @Test
    void createSslCertificate_permissionDenied_throwsPermanent() {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenThrow(pd);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class);
        }
    }

    @Test
    void createSslCertificate_missingPrivateKey_throwsCertInvalid() {
        CertificateBundle noKey = new CertificateBundle(null, "leaf", null, "leaf");
        assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                .createSslCertificate("proj", "global", "id", noKey, mock(GoogleCredentials.class)))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CERT_INVALID");
    }

    @Test
    void createSslCertificate_blankPrivateKey_throwsCertInvalid() {
        CertificateBundle blankKey = new CertificateBundle("  ", "leaf", null, "leaf");
        assertThatThrownBy(() -> new GcpComputeSslCertificateService()
                .createSslCertificate("proj", "global", "id", blankKey, mock(GoogleCredentials.class)))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CERT_INVALID");
    }

    @Test
    void createSslCertificate_fullChainPrefered_overLeaf() throws Exception {
        // When fullChain is present (non-blank) it should be selected over leafCertificate.
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.insertAsync(anyString(), any(SslCertificate.class))).thenReturn(op);
        CertificateBundle b = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----",
                "leaf-only",
                null,
                "full-chain-here");
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            new GcpComputeSslCertificateService()
                    .createSslCertificate("proj", "global", "id", b, mock(GoogleCredentials.class));
        }
    }

    // ===================== deleteSslCertificate =====================

    @Test
    void deleteSslCertificate_blankName_isNoop() {
        new GcpComputeSslCertificateService().deleteSslCertificate(null, mock(GoogleCredentials.class));
        new GcpComputeSslCertificateService().deleteSslCertificate("", mock(GoogleCredentials.class));
        new GcpComputeSslCertificateService().deleteSslCertificate("   ", mock(GoogleCredentials.class));
    }

    @Test
    void deleteSslCertificate_unrecognizedName_isNoop() {
        // No recognized shape — logs and returns; never opens client.
        new GcpComputeSslCertificateService().deleteSslCertificate(
                "projects/p/locations/global/certificates/some-cm", mock(GoogleCredentials.class));
        new GcpComputeSslCertificateService().deleteSslCertificate(
                "random-string", mock(GoogleCredentials.class));
    }

    @Test
    void deleteSslCertificate_partialResourceName_success() throws Exception {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.deleteAsync(anyString(), anyString())).thenReturn(op);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            new GcpComputeSslCertificateService().deleteSslCertificate(
                    "projects/proj/global/sslCertificates/my-cert", mock(GoogleCredentials.class));
        }
    }

    @Test
    void deleteSslCertificate_fullSelfLink_success() throws Exception {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.deleteAsync(anyString(), anyString())).thenReturn(op);
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            new GcpComputeSslCertificateService().deleteSslCertificate(
                    "https://www.googleapis.com/compute/v1/projects/proj/global/sslCertificates/my-cert",
                    mock(GoogleCredentials.class));
        }
    }

    @Test
    void deleteSslCertificate_regionalSelfLink_deletesInThatRegion() throws Exception {
        RegionSslCertificatesClient mockClient = mock(RegionSslCertificatesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.deleteAsync(anyString(), anyString(), anyString())).thenReturn(op);
        try (MockedStatic<RegionSslCertificatesClient> s = mockStatic(RegionSslCertificatesClient.class)) {
            s.when(() -> RegionSslCertificatesClient.create(any(RegionSslCertificatesSettings.class))).thenReturn(mockClient);
            new GcpComputeSslCertificateService().deleteSslCertificate(
                    "https://www.googleapis.com/compute/v1/projects/proj/regions/us-central1/sslCertificates/my-cert",
                    mock(GoogleCredentials.class));
            verify(mockClient).deleteAsync("proj", "us-central1", "my-cert");
        }
    }

    @Test
    void deleteSslCertificate_failure_isSwallowedBestEffort() {
        SslCertificatesClient mockClient = mock(SslCertificatesClient.class);
        when(mockClient.deleteAsync(anyString(), anyString())).thenThrow(new RuntimeException("boom"));
        try (MockedStatic<SslCertificatesClient> s = mockStatic(SslCertificatesClient.class)) {
            s.when(() -> SslCertificatesClient.create(any(SslCertificatesSettings.class))).thenReturn(mockClient);
            // No exception escapes.
            new GcpComputeSslCertificateService().deleteSslCertificate(
                    "projects/proj/global/sslCertificates/my-cert", mock(GoogleCredentials.class));
        }
    }
}

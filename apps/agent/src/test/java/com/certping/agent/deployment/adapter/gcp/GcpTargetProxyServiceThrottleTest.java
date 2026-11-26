// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.google.api.gax.longrunning.OperationFuture;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.ApiExceptionFactory;
import com.google.api.gax.rpc.NotFoundException;
import com.google.api.gax.rpc.PermissionDeniedException;
import com.google.api.gax.rpc.ResourceExhaustedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.api.gax.rpc.UnauthenticatedException;
import com.google.api.gax.rpc.UnavailableException;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.compute.v1.RegionTargetHttpsProxiesClient;
import com.google.cloud.compute.v1.RegionTargetHttpsProxiesSetSslCertificatesRequest;
import com.google.cloud.compute.v1.RegionTargetHttpsProxiesSettings;
import com.google.cloud.compute.v1.TargetHttpsProxiesClient;
import com.google.cloud.compute.v1.TargetHttpsProxiesSetSslCertificatesRequest;
import com.google.cloud.compute.v1.TargetHttpsProxiesSettings;
import com.google.cloud.compute.v1.TargetHttpsProxy;
import com.google.cloud.compute.v1.TargetSslProxiesClient;
import com.google.cloud.compute.v1.TargetSslProxiesSetSslCertificatesRequest;
import com.google.cloud.compute.v1.TargetSslProxiesSettings;
import com.google.cloud.compute.v1.TargetSslProxy;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Coverage for {@link GcpTargetProxyService} client methods — global + regional, HTTPS + SSL
 * proxy paths, and the throttle / auth / not-found exception arms.
 */
class GcpTargetProxyServiceThrottleTest {

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

    private static GcpTargetProxyConfig globalCfg() {
        return new GcpTargetProxyConfig("proj", "global", "my-proxy");
    }

    private static GcpTargetProxyConfig regionalCfg() {
        return new GcpTargetProxyConfig("proj", "us-east1", "my-proxy");
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static OperationFuture operationOf(Object result) throws Exception {
        OperationFuture f = mock(OperationFuture.class);
        org.mockito.Mockito.doReturn(result).when(f).get();
        return f;
    }

    // ===================== fetchHttpsProxy (global) =====================

    @Test
    void fetchHttpsProxy_resourceExhausted_throwsRetryableThrottle() {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        ResourceExhaustedException throttle = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.get(anyString(), anyString())).thenThrow(throttle);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().fetchHttpsProxy(globalCfg(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void fetchHttpsProxy_success_denormalizes() {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        TargetHttpsProxy proxy = TargetHttpsProxy.newBuilder()
                .addSslCertificates("//certificatemanager.googleapis.com/projects/p/locations/global/certificates/c1")
                .addSslCertificates("https://www.googleapis.com/compute/v1/projects/p/global/sslCertificates/native")
                .build();
        when(mockClient.get(anyString(), anyString())).thenReturn(proxy);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            List<String> r = new GcpTargetProxyService().fetchHttpsProxy(globalCfg(), mock(GoogleCredentials.class)).sslCertificates();
            assertThat(r).containsExactly(
                    "projects/p/locations/global/certificates/c1",
                    "https://www.googleapis.com/compute/v1/projects/p/global/sslCertificates/native");
        }
    }

    @Test
    void fetchHttpsProxy_certificateMapAttached_returnsTheMap() {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        TargetHttpsProxy proxy = TargetHttpsProxy.newBuilder()
                .setCertificateMap("//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/m")
                .build();
        when(mockClient.get(anyString(), anyString())).thenReturn(proxy);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            GcpTargetProxyState state = new GcpTargetProxyService().fetchHttpsProxy(globalCfg(), mock(GoogleCredentials.class));
            assertThat(state.usesCertificateMap()).isTrue();
            assertThat(state.certificateMap())
                    .isEqualTo("//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/m");
        }
    }

    @Test
    void fetchSslProxy_certificateMapAttached_returnsTheMap() {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        TargetSslProxy proxy = TargetSslProxy.newBuilder()
                .setCertificateMap("//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/m")
                .build();
        when(mockClient.get(anyString(), anyString())).thenReturn(proxy);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            GcpTargetProxyState state = new GcpTargetProxyService().fetchSslProxy(globalCfg(), mock(GoogleCredentials.class));
            assertThat(state.usesCertificateMap()).isTrue();
            assertThat(state.certificateMap())
                    .isEqualTo("//certificatemanager.googleapis.com/projects/p/locations/global/certificateMaps/m");
        }
    }

    @Test
    void fetchHttpsProxy_unauthenticated_throwsPermanent() {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        UnauthenticatedException ue = fakeApi(StatusCode.Code.UNAUTHENTICATED, 401, UnauthenticatedException.class);
        when(mockClient.get(anyString(), anyString())).thenThrow(ue);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().fetchHttpsProxy(globalCfg(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        }
    }

    // ===================== fetchHttpsProxy (regional) =====================

    @Test
    void fetchHttpsProxy_regional_success() {
        RegionTargetHttpsProxiesClient mockClient = mock(RegionTargetHttpsProxiesClient.class);
        com.google.cloud.compute.v1.TargetHttpsProxy proxy = com.google.cloud.compute.v1.TargetHttpsProxy.newBuilder()
                .addSslCertificates("projects/p/regions/us-east1/sslCertificates/n1").build();
        when(mockClient.get(anyString(), anyString(), anyString())).thenReturn(proxy);
        try (MockedStatic<RegionTargetHttpsProxiesClient> s = mockStatic(RegionTargetHttpsProxiesClient.class)) {
            s.when(() -> RegionTargetHttpsProxiesClient.create(any(RegionTargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            List<String> r = new GcpTargetProxyService().fetchHttpsProxy(regionalCfg(), mock(GoogleCredentials.class)).sslCertificates();
            assertThat(r).containsExactly("projects/p/regions/us-east1/sslCertificates/n1");
        }
    }

    @Test
    void fetchHttpsProxy_regional_throttle_throwsRetryable() {
        RegionTargetHttpsProxiesClient mockClient = mock(RegionTargetHttpsProxiesClient.class);
        UnavailableException ue = fakeApi(StatusCode.Code.UNAVAILABLE, 503, UnavailableException.class);
        when(mockClient.get(anyString(), anyString(), anyString())).thenThrow(ue);
        try (MockedStatic<RegionTargetHttpsProxiesClient> s = mockStatic(RegionTargetHttpsProxiesClient.class)) {
            s.when(() -> RegionTargetHttpsProxiesClient.create(any(RegionTargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().fetchHttpsProxy(regionalCfg(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void fetchHttpsProxy_regional_notFound_throwsPermanent() {
        RegionTargetHttpsProxiesClient mockClient = mock(RegionTargetHttpsProxiesClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        when(mockClient.get(anyString(), anyString(), anyString())).thenThrow(nf);
        try (MockedStatic<RegionTargetHttpsProxiesClient> s = mockStatic(RegionTargetHttpsProxiesClient.class)) {
            s.when(() -> RegionTargetHttpsProxiesClient.create(any(RegionTargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().fetchHttpsProxy(regionalCfg(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        }
    }

    // ===================== applyHttpsProxyCertificates =====================

    @Test
    void applyHttpsProxyCertificates_global_success() throws Exception {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(),
                any(TargetHttpsProxiesSetSslCertificatesRequest.class))).thenReturn(op);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            new GcpTargetProxyService().applyHttpsProxyCertificates(globalCfg(), mock(GoogleCredentials.class),
                    List.of("projects/p/locations/global/certificates/c1"));
        }
    }

    @Test
    void applyHttpsProxyCertificates_global_throttle_throwsRetryable() {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        ResourceExhaustedException re = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(),
                any(TargetHttpsProxiesSetSslCertificatesRequest.class))).thenThrow(re);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().applyHttpsProxyCertificates(
                    globalCfg(), mock(GoogleCredentials.class), List.of("c")))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void applyHttpsProxyCertificates_global_permissionDenied_throwsPermanent() {
        TargetHttpsProxiesClient mockClient = mock(TargetHttpsProxiesClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(),
                any(TargetHttpsProxiesSetSslCertificatesRequest.class))).thenThrow(pd);
        try (MockedStatic<TargetHttpsProxiesClient> s = mockStatic(TargetHttpsProxiesClient.class)) {
            s.when(() -> TargetHttpsProxiesClient.create(any(TargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().applyHttpsProxyCertificates(
                    globalCfg(), mock(GoogleCredentials.class), List.of("c")))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        }
    }

    @Test
    void applyHttpsProxyCertificates_regional_success() throws Exception {
        RegionTargetHttpsProxiesClient mockClient = mock(RegionTargetHttpsProxiesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(), anyString(),
                any(RegionTargetHttpsProxiesSetSslCertificatesRequest.class))).thenReturn(op);
        try (MockedStatic<RegionTargetHttpsProxiesClient> s = mockStatic(RegionTargetHttpsProxiesClient.class)) {
            s.when(() -> RegionTargetHttpsProxiesClient.create(any(RegionTargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            new GcpTargetProxyService().applyHttpsProxyCertificates(regionalCfg(), mock(GoogleCredentials.class),
                    List.of("projects/p/locations/us-east1/certificates/c1"));
        }
    }

    @Test
    void applyHttpsProxyCertificates_regional_throttle_throwsRetryable() {
        RegionTargetHttpsProxiesClient mockClient = mock(RegionTargetHttpsProxiesClient.class);
        ResourceExhaustedException re = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(), anyString(),
                any(RegionTargetHttpsProxiesSetSslCertificatesRequest.class))).thenThrow(re);
        try (MockedStatic<RegionTargetHttpsProxiesClient> s = mockStatic(RegionTargetHttpsProxiesClient.class)) {
            s.when(() -> RegionTargetHttpsProxiesClient.create(any(RegionTargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().applyHttpsProxyCertificates(
                    regionalCfg(), mock(GoogleCredentials.class), List.of("c")))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void applyHttpsProxyCertificates_regional_otherFailure_throwsPermanent() {
        RegionTargetHttpsProxiesClient mockClient = mock(RegionTargetHttpsProxiesClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(), anyString(),
                any(RegionTargetHttpsProxiesSetSslCertificatesRequest.class))).thenThrow(nf);
        try (MockedStatic<RegionTargetHttpsProxiesClient> s = mockStatic(RegionTargetHttpsProxiesClient.class)) {
            s.when(() -> RegionTargetHttpsProxiesClient.create(any(RegionTargetHttpsProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().applyHttpsProxyCertificates(
                    regionalCfg(), mock(GoogleCredentials.class), List.of("c")))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        }
    }

    // ===================== fetchSslProxy =====================

    @Test
    void fetchSslProxy_global_success() {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        TargetSslProxy proxy = TargetSslProxy.newBuilder()
                .addSslCertificates("projects/p/global/sslCertificates/native").build();
        when(mockClient.get(anyString(), anyString())).thenReturn(proxy);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            List<String> r = new GcpTargetProxyService().fetchSslProxy(globalCfg(), mock(GoogleCredentials.class)).sslCertificates();
            assertThat(r).containsExactly("projects/p/global/sslCertificates/native");
        }
    }

    @Test
    void fetchSslProxy_global_throttle_throwsRetryable() {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        ResourceExhaustedException re = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.get(anyString(), anyString())).thenThrow(re);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().fetchSslProxy(globalCfg(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void fetchSslProxy_global_unauthenticated_throwsPermanent() {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        UnauthenticatedException ue = fakeApi(StatusCode.Code.UNAUTHENTICATED, 401, UnauthenticatedException.class);
        when(mockClient.get(anyString(), anyString())).thenThrow(ue);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().fetchSslProxy(globalCfg(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        }
    }

    @Test
    void fetchSslProxy_regional_alwaysThrowsPermanent() {
        // Regional Target SSL Proxies are not supported by the SDK in this build.
        assertThatThrownBy(() -> new GcpTargetProxyService().fetchSslProxy(regionalCfg(), mock(GoogleCredentials.class)))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
    }

    // ===================== applySslProxyCertificates =====================

    @Test
    void applySslProxyCertificates_global_success() throws Exception {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        OperationFuture op = operationOf(null);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(),
                any(TargetSslProxiesSetSslCertificatesRequest.class))).thenReturn(op);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            new GcpTargetProxyService().applySslProxyCertificates(globalCfg(), mock(GoogleCredentials.class),
                    List.of("projects/p/global/sslCertificates/c"));
        }
    }

    @Test
    void applySslProxyCertificates_global_throttle_throwsRetryable() {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        UnavailableException ue = fakeApi(StatusCode.Code.UNAVAILABLE, 503, UnavailableException.class);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(),
                any(TargetSslProxiesSetSslCertificatesRequest.class))).thenThrow(ue);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().applySslProxyCertificates(
                    globalCfg(), mock(GoogleCredentials.class), List.of("c")))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void applySslProxyCertificates_global_permissionDenied_throwsPermanent() {
        TargetSslProxiesClient mockClient = mock(TargetSslProxiesClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.setSslCertificatesAsync(anyString(), anyString(),
                any(TargetSslProxiesSetSslCertificatesRequest.class))).thenThrow(pd);
        try (MockedStatic<TargetSslProxiesClient> s = mockStatic(TargetSslProxiesClient.class)) {
            s.when(() -> TargetSslProxiesClient.create(any(TargetSslProxiesSettings.class))).thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpTargetProxyService().applySslProxyCertificates(
                    globalCfg(), mock(GoogleCredentials.class), List.of("c")))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        }
    }

    @Test
    void applySslProxyCertificates_regional_alwaysThrowsPermanent() {
        assertThatThrownBy(() -> new GcpTargetProxyService().applySslProxyCertificates(
                regionalCfg(), mock(GoogleCredentials.class), List.of("c")))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
    }
}

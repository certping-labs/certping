// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.google.api.gax.longrunning.OperationFuture;
import com.google.api.gax.rpc.AlreadyExistsException;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.ApiExceptionFactory;
import com.google.api.gax.rpc.FailedPreconditionException;
import com.google.api.gax.rpc.InvalidArgumentException;
import com.google.api.gax.rpc.NotFoundException;
import com.google.api.gax.rpc.PermissionDeniedException;
import com.google.api.gax.rpc.ResourceExhaustedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.api.gax.rpc.UnauthenticatedException;
import com.google.api.gax.rpc.UnavailableException;
import com.google.api.core.ApiFuture;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.certificatemanager.v1.Certificate;
import com.google.cloud.certificatemanager.v1.CertificateManagerClient;
import com.google.cloud.certificatemanager.v1.CertificateManagerSettings;
import com.google.cloud.certificatemanager.v1.CertificateMapEntry;
import com.google.cloud.certificatemanager.v1.CertificateMapName;
import com.google.cloud.certificatemanager.v1.LocationName;
import com.google.cloud.certificatemanager.v1.UpdateCertificateMapEntryRequest;
import com.google.cloud.certificatemanager.v1.UpdateCertificateRequest;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Coverage for {@link GcpCertificateManagerService} — exercises every public method, including
 * happy-path, idempotent-update, throttle, NotFound, ALREADY_EXISTS, and miscellaneous error arms.
 */
class GcpCertificateManagerServiceThrottleTest {

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

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static OperationFuture operationFailing(Throwable cause) throws Exception {
        OperationFuture f = mock(OperationFuture.class);
        org.mockito.Mockito.doThrow(new ExecutionException(cause)).when(f).get();
        return f;
    }

    // ===================== createCertificate =====================

    @Test
    void createCertificate_resourceExhausted_throwsRetryableThrottle() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        ResourceExhaustedException throttle = fakeApi(
                StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.createCertificateAsync(any(LocationName.class), any(Certificate.class), any(String.class)))
                .thenThrow(throttle);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .createCertificate("p", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(ex -> assertThat(((RetryableAgentException) ex).getErrorCode())
                            .isEqualTo("DEPLOY_PROVIDER_THROTTLED"));
        }
    }

    @Test
    void createCertificate_success_returnsName() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        Certificate created = Certificate.newBuilder()
                .setName("projects/p/locations/global/certificates/x").build();
        OperationFuture op = operationOf(created);
        when(mockClient.createCertificateAsync(any(LocationName.class), any(Certificate.class), any(String.class)))
                .thenReturn(op);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            String name = new GcpCertificateManagerService()
                    .createCertificate("p", "global", "x", bundle(), mock(GoogleCredentials.class));
            assertThat(name).isEqualTo("projects/p/locations/global/certificates/x");
        }
    }

    @Test
    void createCertificate_emptyReturnedName_throwsPermanentNullResourceId() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        Certificate created = Certificate.newBuilder().setName("").build();
        OperationFuture op = operationOf(created);
        when(mockClient.createCertificateAsync(any(LocationName.class), any(Certificate.class), any(String.class)))
                .thenReturn(op);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .createCertificate("p", "global", "x", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_RESULT_NULL_RESOURCE_ID");
        }
    }

    @Test
    void createCertificate_alreadyExists_thenUpdateSucceeds_returnsExistingName() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        AlreadyExistsException ae = fakeApi(
                StatusCode.Code.ALREADY_EXISTS, 409, AlreadyExistsException.class);
        when(mockClient.createCertificateAsync(any(LocationName.class), any(Certificate.class), any(String.class)))
                .thenThrow(ae);
        Certificate updated = Certificate.newBuilder().setName("projects/p/locations/global/certificates/id").build();
        OperationFuture op2 = operationOf(updated);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class)))
                .thenReturn(op2);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            String name = new GcpCertificateManagerService()
                    .createCertificate("p", "global", "id", bundle(), mock(GoogleCredentials.class));
            assertThat(name).isEqualTo("projects/p/locations/global/certificates/id");
        }
    }

    @Test
    void createCertificate_alreadyExists_updateRejected_throwsResourceConflict() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        AlreadyExistsException ae = fakeApi(
                StatusCode.Code.ALREADY_EXISTS, 409, AlreadyExistsException.class);
        when(mockClient.createCertificateAsync(any(LocationName.class), any(Certificate.class), any(String.class)))
                .thenThrow(ae);
        // Update fails with InvalidArgument (SAN mismatch) — returns false from updateCertificate.
        InvalidArgumentException iae = fakeApi(
                StatusCode.Code.INVALID_ARGUMENT, 400, InvalidArgumentException.class);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class))).thenThrow(iae);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .createCertificate("p", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_RESOURCE_CONFLICT");
        }
    }

    @Test
    void createCertificate_unauthenticated_throwsPermanent() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        UnauthenticatedException ue = fakeApi(
                StatusCode.Code.UNAUTHENTICATED, 401, UnauthenticatedException.class);
        when(mockClient.createCertificateAsync(any(LocationName.class), any(Certificate.class), any(String.class)))
                .thenThrow(ue);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .createCertificate("p", "global", "id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_CERT_MANAGER_FAILED");
        }
    }

    @Test
    void createCertificate_missingPrivateKey_throwsCertInvalid() {
        CertificateBundle noKey = new CertificateBundle(null, "leaf", null, "leaf");
        assertThatThrownBy(() -> new GcpCertificateManagerService()
                .createCertificate("p", "global", "id", noKey, mock(GoogleCredentials.class)))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CERT_INVALID");
    }

    // ===================== updateCertificate =====================

    @Test
    void updateCertificate_blankName_returnsFalse() {
        assertThat(new GcpCertificateManagerService()
                .updateCertificate("", bundle(), mock(GoogleCredentials.class))).isFalse();
        assertThat(new GcpCertificateManagerService()
                .updateCertificate(null, bundle(), mock(GoogleCredentials.class))).isFalse();
    }

    @Test
    void updateCertificate_success_returnsTrue() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        OperationFuture op = operationOf(Certificate.newBuilder().setName("x").build());
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class)))
                .thenReturn(op);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            boolean ok = new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class));
            assertThat(ok).isTrue();
        }
    }

    @Test
    void updateCertificate_notFound_returnsFalseFallback() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class))).thenThrow(nf);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThat(new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class)))
                    .isFalse();
        }
    }

    @Test
    void updateCertificate_failedPrecondition_returnsFalseFallback() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        FailedPreconditionException fp = fakeApi(StatusCode.Code.FAILED_PRECONDITION, 400, FailedPreconditionException.class);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class))).thenThrow(fp);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThat(new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class)))
                    .isFalse();
        }
    }

    @Test
    void updateCertificate_invalidArgument_returnsFalseFallback() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        InvalidArgumentException iae = fakeApi(StatusCode.Code.INVALID_ARGUMENT, 400, InvalidArgumentException.class);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class))).thenThrow(iae);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThat(new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class)))
                    .isFalse();
        }
    }

    @Test
    void updateCertificate_throttle_throwsRetryable() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        ResourceExhaustedException throttle = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class))).thenThrow(throttle);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void updateCertificate_permissionDenied_throwsPermanent() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class))).thenThrow(pd);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_CERT_UPDATE_FAILED");
        }
    }

    @Test
    void updateCertificate_executionCauseNotFound_returnsFalseFallback() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        OperationFuture failingOp = operationFailing(nf);
        when(mockClient.updateCertificateAsync(any(UpdateCertificateRequest.class)))
                .thenReturn(failingOp);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThat(new GcpCertificateManagerService()
                    .updateCertificate("projects/p/locations/global/certificates/id", bundle(), mock(GoogleCredentials.class)))
                    .isFalse();
        }
    }

    // ===================== deleteCertificate =====================

    @Test
    void deleteCertificate_blankName_isNoop() {
        // Doesn't throw, doesn't open client.
        new GcpCertificateManagerService().deleteCertificate(null, mock(GoogleCredentials.class));
        new GcpCertificateManagerService().deleteCertificate("", mock(GoogleCredentials.class));
    }

    @Test
    void deleteCertificate_success_returnsNormally() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        OperationFuture op = operationOf(com.google.protobuf.Empty.getDefaultInstance());
        when(mockClient.deleteCertificateAsync(any(String.class))).thenReturn(op);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            new GcpCertificateManagerService().deleteCertificate("projects/p/locations/global/certificates/id",
                    mock(GoogleCredentials.class));
        }
    }

    @Test
    void deleteCertificate_notFound_swallowsAsInfo() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        when(mockClient.deleteCertificateAsync(any(String.class))).thenThrow(nf);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            new GcpCertificateManagerService().deleteCertificate("projects/p/locations/global/certificates/id",
                    mock(GoogleCredentials.class));
        }
    }

    @Test
    void deleteCertificate_executionCauseNotFound_swallowsAsInfo() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        OperationFuture failingOp = operationFailing(nf);
        when(mockClient.deleteCertificateAsync(any(String.class))).thenReturn(failingOp);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            new GcpCertificateManagerService().deleteCertificate("projects/p/locations/global/certificates/id",
                    mock(GoogleCredentials.class));
        }
    }

    @Test
    void deleteCertificate_otherFailure_isSwallowedAsBestEffort() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        when(mockClient.deleteCertificateAsync(any(String.class)))
                .thenThrow(new RuntimeException("boom"));
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            // Best-effort: no exception escapes.
            new GcpCertificateManagerService().deleteCertificate("projects/p/locations/global/certificates/id",
                    mock(GoogleCredentials.class));
        }
    }

    // ===================== listEntriesByHostname =====================

    @Test
    void listEntriesByHostname_blankMap_returnsEmpty() {
        Map<String, String> r = new GcpCertificateManagerService()
                .listEntriesByHostname("p", "global", " ", mock(GoogleCredentials.class));
        assertThat(r).isEmpty();
        Map<String, String> r2 = new GcpCertificateManagerService()
                .listEntriesByHostname("p", "global", null, mock(GoogleCredentials.class));
        assertThat(r2).isEmpty();
    }

    @Test
    void listEntriesByHostname_success_normalizesHostnames() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        CertificateManagerClient.ListCertificateMapEntriesPagedResponse paged =
                mock(CertificateManagerClient.ListCertificateMapEntriesPagedResponse.class);
        when(mockClient.listCertificateMapEntries(any(CertificateMapName.class))).thenReturn(paged);
        List<CertificateMapEntry> entries = new ArrayList<>();
        entries.add(CertificateMapEntry.newBuilder().setHostname("API.Example.com")
                .setName("projects/p/locations/global/certificateMaps/m/entries/a").build());
        entries.add(CertificateMapEntry.newBuilder().setHostname("")
                .setName("projects/p/locations/global/certificateMaps/m/entries/empty").build());
        entries.add(CertificateMapEntry.newBuilder().setHostname("*.example.com")
                .setName("projects/p/locations/global/certificateMaps/m/entries/wc").build());
        when(paged.iterateAll()).thenReturn(entries);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            Map<String, String> r = new GcpCertificateManagerService()
                    .listEntriesByHostname("p", "global", "m", mock(GoogleCredentials.class));
            assertThat(r).containsOnlyKeys("api.example.com", "*.example.com");
        }
    }

    @Test
    void listEntriesByHostname_notFound_returnsEmpty() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        NotFoundException nf = fakeApi(StatusCode.Code.NOT_FOUND, 404, NotFoundException.class);
        when(mockClient.listCertificateMapEntries(any(CertificateMapName.class))).thenThrow(nf);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            Map<String, String> r = new GcpCertificateManagerService()
                    .listEntriesByHostname("p", "global", "m", mock(GoogleCredentials.class));
            assertThat(r).isEmpty();
        }
    }

    @Test
    void listEntriesByHostname_throttle_throwsRetryable() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        UnavailableException ue = fakeApi(StatusCode.Code.UNAVAILABLE, 503, UnavailableException.class);
        when(mockClient.listCertificateMapEntries(any(CertificateMapName.class))).thenThrow(ue);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .listEntriesByHostname("p", "global", "m", mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void listEntriesByHostname_otherFailure_throwsPermanent() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.listCertificateMapEntries(any(CertificateMapName.class))).thenThrow(pd);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .listEntriesByHostname("p", "global", "m", mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_CERT_MAP_FAILED");
        }
    }

    // ===================== updateMapEntryCertificates =====================

    @Test
    void updateMapEntryCertificates_success_returnsName() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        CertificateMapEntry resp = CertificateMapEntry.newBuilder().setName("entry-x").build();
        OperationFuture op = operationOf(resp);
        when(mockClient.updateCertificateMapEntryAsync(any(UpdateCertificateMapEntryRequest.class)))
                .thenReturn(op);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            String r = new GcpCertificateManagerService()
                    .updateMapEntryCertificates("entry-x", "cert-x", mock(GoogleCredentials.class));
            assertThat(r).isEqualTo("entry-x");
        }
    }

    @Test
    void updateMapEntryCertificates_throttle_throwsRetryable() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        ResourceExhaustedException throttle = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.updateCertificateMapEntryAsync(any(UpdateCertificateMapEntryRequest.class))).thenThrow(throttle);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .updateMapEntryCertificates("entry-x", "cert-x", mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void updateMapEntryCertificates_permissionDenied_throwsPermanent() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.updateCertificateMapEntryAsync(any(UpdateCertificateMapEntryRequest.class))).thenThrow(pd);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .updateMapEntryCertificates("entry-x", "cert-x", mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_CERT_MAP_FAILED");
        }
    }

    // ===================== createMapEntry =====================

    @Test
    void createMapEntry_success_returnsName() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        CertificateMapEntry resp = CertificateMapEntry.newBuilder().setName("entry-new").build();
        OperationFuture op = operationOf(resp);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class)))
                .thenReturn(op);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            String r = new GcpCertificateManagerService()
                    .createMapEntry("p", "global", "m", "eid", "host.x", "cert", mock(GoogleCredentials.class));
            assertThat(r).isEqualTo("entry-new");
        }
    }

    @Test
    void createMapEntry_throttle_throwsRetryable() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        ResourceExhaustedException re = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class))).thenThrow(re);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .createMapEntry("p", "global", "m", "eid", "host.x", "cert", mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void createMapEntry_permissionDenied_throwsPermanent() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class))).thenThrow(pd);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .createMapEntry("p", "global", "m", "eid", "host.x", "cert", mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_CERT_MAP_FAILED");
        }
    }

    // ===================== upsertCertificateMapEntry =====================

    @Test
    void upsertCertificateMapEntry_blankMap_returnsNull() {
        String r = new GcpCertificateManagerService()
                .upsertCertificateMapEntry("p", "global", "", "eid", "host", "cert", mock(GoogleCredentials.class));
        assertThat(r).isNull();
        String r2 = new GcpCertificateManagerService()
                .upsertCertificateMapEntry("p", "global", null, "eid", "host", "cert", mock(GoogleCredentials.class));
        assertThat(r2).isNull();
    }

    @Test
    void upsertCertificateMapEntry_createSuccess_returnsName() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        CertificateMapEntry resp = CertificateMapEntry.newBuilder().setName("entry-new").build();
        OperationFuture op = operationOf(resp);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class)))
                .thenReturn(op);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            String r = new GcpCertificateManagerService()
                    .upsertCertificateMapEntry("p", "global", "m", "", "host.x", "cert", mock(GoogleCredentials.class));
            assertThat(r).isEqualTo("entry-new");
        }
    }

    @Test
    void upsertCertificateMapEntry_alreadyExists_fallsBackToUpdate() throws Exception {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        AlreadyExistsException ae = fakeApi(StatusCode.Code.ALREADY_EXISTS, 409, AlreadyExistsException.class);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class))).thenThrow(ae);
        CertificateMapEntry updated = CertificateMapEntry.newBuilder().setName("entry-updated").build();
        OperationFuture op = operationOf(updated);
        when(mockClient.updateCertificateMapEntryAsync(any(UpdateCertificateMapEntryRequest.class)))
                .thenReturn(op);

        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            String r = new GcpCertificateManagerService()
                    .upsertCertificateMapEntry("p", "global", "m", "eid", "host.x", "cert", mock(GoogleCredentials.class));
            assertThat(r).isEqualTo("entry-updated");
        }
    }

    @Test
    void upsertCertificateMapEntry_throttle_throwsRetryable() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        ResourceExhaustedException re = fakeApi(StatusCode.Code.RESOURCE_EXHAUSTED, 429, ResourceExhaustedException.class);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class))).thenThrow(re);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .upsertCertificateMapEntry("p", "global", "m", "eid", "host.x", "cert", mock(GoogleCredentials.class)))
                    .isInstanceOf(RetryableAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_PROVIDER_THROTTLED");
        }
    }

    @Test
    void upsertCertificateMapEntry_permissionDenied_throwsPermanent() {
        CertificateManagerClient mockClient = mock(CertificateManagerClient.class);
        PermissionDeniedException pd = fakeApi(StatusCode.Code.PERMISSION_DENIED, 403, PermissionDeniedException.class);
        when(mockClient.createCertificateMapEntryAsync(any(CertificateMapName.class),
                any(CertificateMapEntry.class), any(String.class))).thenThrow(pd);
        try (MockedStatic<CertificateManagerClient> s = mockStatic(CertificateManagerClient.class)) {
            s.when(() -> CertificateManagerClient.create(any(CertificateManagerSettings.class)))
                    .thenReturn(mockClient);
            assertThatThrownBy(() -> new GcpCertificateManagerService()
                    .upsertCertificateMapEntry("p", "global", "m", "eid", "host.x", "cert", mock(GoogleCredentials.class)))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_CERT_MAP_FAILED");
        }
    }
}

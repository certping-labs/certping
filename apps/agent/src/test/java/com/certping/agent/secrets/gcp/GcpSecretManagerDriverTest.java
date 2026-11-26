// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.gcp;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProperties.GcpAuthMode;
import com.certping.agent.secrets.SecretStoreProperties.GcpSecretManagerProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import com.google.api.gax.rpc.AlreadyExistsException;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.NotFoundException;
import com.google.api.gax.rpc.PermissionDeniedException;
import com.google.api.gax.rpc.ResourceExhaustedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.api.gax.rpc.UnavailableException;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.AddSecretVersionRequest;
import com.google.cloud.secretmanager.v1.CreateSecretRequest;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.cloud.secretmanager.v1.SecretVersion;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GcpSecretManagerDriverTest {

    private static final String PROJECT = "certping-test";
    private static final String PREFIX = "agent-";
    private static final String OWN_SECRET_NAME = PREFIX + "cert-1";
    private static final String OWN_HANDLE_LATEST =
            "projects/" + PROJECT + "/secrets/" + OWN_SECRET_NAME + "/versions/latest";
    private static final String OWN_HANDLE_V1 =
            "projects/" + PROJECT + "/secrets/" + OWN_SECRET_NAME + "/versions/1";
    private static final String FOREIGN_HANDLE =
            "projects/other-project/secrets/foreign/versions/latest";

    private SecretStoreProperties props;
    private SecretManagerServiceClient client;
    private GcpSecretManagerDriver driver;

    @BeforeEach
    void setUp() {
        props = new SecretStoreProperties();
        GcpSecretManagerProperties gcp = props.getGcpSecretManager();
        gcp.setProjectId(PROJECT);
        gcp.setOwnStoreSecretPrefix(PREFIX);
        gcp.setAuthMode(GcpAuthMode.ADC);
        client = mock(SecretManagerServiceClient.class);
        driver = new GcpSecretManagerDriver(props, "test", client);
    }

    @Test
    void provider_returnsGcpSecretManager() {
        assertThat(driver.provider()).isEqualTo(SecretStoreProvider.GCP_SECRET_MANAGER);
    }

    @Test
    void parsesHandle_acceptsCanonicalAndLatest() {
        assertThat(driver.parsesHandle(OWN_HANDLE_LATEST)).isTrue();
        assertThat(driver.parsesHandle(OWN_HANDLE_V1)).isTrue();
        assertThat(driver.parsesHandle(FOREIGN_HANDLE)).isTrue();
    }

    @Test
    void parsesHandle_rejectsMalformed() {
        assertThat(driver.parsesHandle(null)).isFalse();
        assertThat(driver.parsesHandle("")).isFalse();
        assertThat(driver.parsesHandle("projects/x/secrets/y")).isFalse();
        assertThat(driver.parsesHandle("garbage")).isFalse();
    }

    @Test
    void assertValidName_acceptsSubset() {
        assertThatCode(() -> driver.assertValidName("cert_1-abc")).doesNotThrowAnyException();
    }

    @Test
    void assertValidName_rejectsForbidden() {
        assertThatThrownBy(() -> driver.assertValidName(null))
                .isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.assertValidName("has space"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void isOwnedByThisAgent_true_forOwnProjectAndPrefix() {
        assertThat(driver.isOwnedByThisAgent(OWN_HANDLE_LATEST)).isTrue();
    }

    @Test
    void isOwnedByThisAgent_false_forDifferentProject() {
        assertThat(driver.isOwnedByThisAgent(FOREIGN_HANDLE)).isFalse();
    }

    @Test
    void isOwnedByThisAgent_false_forDifferentPrefix() {
        String other = "projects/" + PROJECT + "/secrets/other-cert-1/versions/latest";
        assertThat(driver.isOwnedByThisAgent(other)).isFalse();
    }

    @Test
    void isOwnedByThisAgent_false_forMalformed() {
        assertThat(driver.isOwnedByThisAgent("garbage")).isFalse();
        assertThat(driver.isOwnedByThisAgent(null)).isFalse();
    }

    @Test
    void handleFor_returnsCanonicalPath() {
        assertThat(driver.handleFor("cert-1"))
                .isEqualTo("projects/" + PROJECT + "/secrets/agent-cert-1/versions/latest");
    }

    @Test
    void handleFor_rejectsInvalidName() {
        assertThatThrownBy(() -> driver.handleFor("bad name"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- read ----

    @Test
    void read_returnsSecretString() {
        AccessSecretVersionResponse resp = AccessSecretVersionResponse.newBuilder()
                .setPayload(SecretPayload.newBuilder().setData(ByteString.copyFromUtf8("value")).build())
                .build();
        when(client.accessSecretVersion(OWN_HANDLE_LATEST)).thenReturn(resp);
        assertThat(driver.read(OWN_HANDLE_LATEST)).isEqualTo("value");
    }

    @Test
    void read_notFound_throwsPermanent() {
        when(client.accessSecretVersion(anyString())).thenThrow(notFound());
        assertThatThrownBy(() -> driver.read(OWN_HANDLE_LATEST))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("SM_SECRET_NOT_FOUND"));
    }

    @Test
    void read_permissionDenied_throwsPermanent() {
        when(client.accessSecretVersion(anyString())).thenThrow(permissionDenied());
        assertThatThrownBy(() -> driver.read(OWN_HANDLE_LATEST))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("SM_ACCESS_DENIED"));
    }

    @Test
    void read_resourceExhausted_throwsRetryable() {
        when(client.accessSecretVersion(anyString())).thenThrow(resourceExhausted());
        assertThatThrownBy(() -> driver.read(OWN_HANDLE_LATEST))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void read_unavailable_throwsRetryable() {
        when(client.accessSecretVersion(anyString())).thenThrow(unavailable());
        assertThatThrownBy(() -> driver.read(OWN_HANDLE_LATEST))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void read_unexpectedError_throwsTransient() {
        when(client.accessSecretVersion(anyString())).thenThrow(new RuntimeException("net"));
        assertThatThrownBy(() -> driver.read(OWN_HANDLE_LATEST))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void read_blankHandle_throwsPermanent() {
        assertThatThrownBy(() -> driver.read("")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.read(null)).isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void read_invalidHandle_throwsPermanent() {
        assertThatThrownBy(() -> driver.read("garbage")).isInstanceOf(PermanentAgentException.class);
    }

    // ---- create ----

    @Test
    void create_createsParentThenAddsVersion() {
        SecretVersion v = SecretVersion.newBuilder()
                .setName("projects/" + PROJECT + "/secrets/agent-cert-1/versions/1").build();
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenReturn(v);
        String h = driver.create("cert-1", "value");
        assertThat(h).endsWith("/versions/1");
        ArgumentCaptor<CreateSecretRequest> cap = ArgumentCaptor.forClass(CreateSecretRequest.class);
        verify(client).createSecret(cap.capture());
        assertThat(cap.getValue().getSecretId()).isEqualTo("agent-cert-1");
    }

    @Test
    void create_skipsParent_whenAlreadyExists() {
        doThrow(alreadyExists()).when(client).createSecret(any(CreateSecretRequest.class));
        SecretVersion v = SecretVersion.newBuilder()
                .setName("projects/" + PROJECT + "/secrets/agent-cert-1/versions/2").build();
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenReturn(v);
        String h = driver.create("cert-1", "value");
        assertThat(h).endsWith("/versions/2");
        verify(client).addSecretVersion(any(AddSecretVersionRequest.class));
    }

    @Test
    void create_permissionDenied_throwsPermanent() {
        doThrow(permissionDenied()).when(client).createSecret(any(CreateSecretRequest.class));
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void create_throttled_throwsRetryable() {
        doThrow(resourceExhausted()).when(client).createSecret(any(CreateSecretRequest.class));
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void create_unexpectedError_throwsTransient() {
        doThrow(new RuntimeException("boom")).when(client).createSecret(any(CreateSecretRequest.class));
        assertThatThrownBy(() -> driver.create("cert-1", "value"))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void create_invalidName_throwsPermanent() {
        assertThatThrownBy(() -> driver.create("bad name", "v"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- update ----

    @Test
    void update_returnsNewVersionResourceName() {
        SecretVersion v = SecretVersion.newBuilder()
                .setName("projects/" + PROJECT + "/secrets/agent-cert-1/versions/3").build();
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenReturn(v);
        assertThat(driver.update(OWN_HANDLE_LATEST, "v"))
                .isEqualTo("projects/" + PROJECT + "/secrets/agent-cert-1/versions/3");
    }

    @Test
    void update_notFound_throwsPermanent() {
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenThrow(notFound());
        assertThatThrownBy(() -> driver.update(OWN_HANDLE_LATEST, "v"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void update_permissionDenied_throwsPermanent() {
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenThrow(permissionDenied());
        assertThatThrownBy(() -> driver.update(OWN_HANDLE_LATEST, "v"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void update_throttled_throwsRetryable() {
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenThrow(resourceExhausted());
        assertThatThrownBy(() -> driver.update(OWN_HANDLE_LATEST, "v"))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void update_unexpectedError_throwsTransient() {
        when(client.addSecretVersion(any(AddSecretVersionRequest.class))).thenThrow(new RuntimeException("net"));
        assertThatThrownBy(() -> driver.update(OWN_HANDLE_LATEST, "v"))
                .isInstanceOf(TransientAgentException.class);
    }

    // ---- delete ----

    @Test
    void delete_ownHandle_callsDelete() {
        driver.delete(OWN_HANDLE_LATEST);
        verify(client).deleteSecret("projects/" + PROJECT + "/secrets/agent-cert-1");
    }

    @Test
    void delete_foreignHandle_refusesSilently() {
        driver.delete(FOREIGN_HANDLE);
        verify(client, never()).deleteSecret(anyString());
    }

    @Test
    void delete_notFound_treatsAsSuccess() {
        doThrow(notFound()).when(client).deleteSecret(anyString());
        assertThatCode(() -> driver.delete(OWN_HANDLE_LATEST)).doesNotThrowAnyException();
    }

    @Test
    void delete_throttled_throwsRetryable() {
        doThrow(resourceExhausted()).when(client).deleteSecret(anyString());
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE_LATEST))
                .isInstanceOf(RetryableAgentException.class);
    }

    @Test
    void delete_apiError_throwsTransient() {
        doThrow(internal()).when(client).deleteSecret(anyString());
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE_LATEST))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void delete_unexpectedError_throwsTransient() {
        doThrow(new RuntimeException("net")).when(client).deleteSecret(anyString());
        assertThatThrownBy(() -> driver.delete(OWN_HANDLE_LATEST))
                .isInstanceOf(TransientAgentException.class);
    }

    // ---- auth-mode init edge cases ----

    @Test
    void init_missingProjectId_throws() {
        SecretStoreProperties p = new SecretStoreProperties();
        p.getGcpSecretManager().setProjectId(null);
        p.getGcpSecretManager().setAuthMode(GcpAuthMode.ADC);
        GcpSecretManagerDriver d = new GcpSecretManagerDriver(p, "test");
        assertThatThrownBy(d::init)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("project-id");
    }

    @Test
    void init_wif_missingConfigFile_throws() {
        props.getGcpSecretManager().setAuthMode(GcpAuthMode.WORKLOAD_IDENTITY_FEDERATION);
        props.getGcpSecretManager().setCredentialConfigFile(null);
        GcpSecretManagerDriver d = new GcpSecretManagerDriver(props, "test");
        assertThatThrownBy(d::init).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("credential-config-file");
    }

    @Test
    void init_saJson_outsideLocalProfile_throws() {
        props.getGcpSecretManager().setAuthMode(GcpAuthMode.SA_JSON);
        props.getGcpSecretManager().setSaJsonFile("/nonexistent/sa.json");
        GcpSecretManagerDriver d = new GcpSecretManagerDriver(props, "prod");
        assertThatThrownBy(d::init).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("local");
    }

    // ---- helpers ----

    private static NotFoundException notFound() {
        return new NotFoundException(new RuntimeException("missing"), fakeStatus(404), false);
    }

    private static PermissionDeniedException permissionDenied() {
        return new PermissionDeniedException(new RuntimeException("denied"), fakeStatus(403), false);
    }

    private static ResourceExhaustedException resourceExhausted() {
        return new ResourceExhaustedException(new RuntimeException("throttled"), fakeStatus(429), true);
    }

    private static UnavailableException unavailable() {
        return new UnavailableException(new RuntimeException("unavail"), fakeStatus(503), true);
    }

    private static AlreadyExistsException alreadyExists() {
        return new AlreadyExistsException(new RuntimeException("exists"), fakeStatus(409), false);
    }

    private static ApiException internal() {
        return new ApiException(new RuntimeException("boom"), fakeStatus(500), false);
    }

    private static StatusCode fakeStatus(int httpCode) {
        return new StatusCode() {
            @Override public Code getCode() { return Code.INTERNAL; }
            @Override public Object getTransportCode() { return httpCode; }
        };
    }
}

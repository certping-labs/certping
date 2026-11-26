// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.gcp;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.api.gax.rpc.ApiCallContext;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.ApiExceptionFactory;
import com.google.api.gax.rpc.StatusCode;
import com.google.api.gax.rpc.UnaryCallable;
import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.DeleteSecretRequest;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.stub.SecretManagerServiceStub;
import com.google.protobuf.Empty;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GcpSecretManagerAgentDriverTest {

    private GcpSecretManagerAgentDriver driverWithFakeProject() throws Exception {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getGcpSecretManager().setProjectId("example-project");
        props.getGcpSecretManager().setOwnStoreSecretPrefix("certping-");
        GcpSecretManagerAgentDriver d = new GcpSecretManagerAgentDriver(
                props, new org.springframework.mock.env.MockEnvironment());
        // Bypass init() (which builds real GCP client). Set fields directly for pure-logic tests.
        setField(d, "projectId", "example-project");
        setField(d, "ownSecretPrefix", "certping-");
        return d;
    }

    @Test
    void provider_returnsGcp() throws Exception {
        assertThat(driverWithFakeProject().provider()).isEqualTo(AgentSecretStoreProvider.GCP_SECRET_MANAGER);
    }

    @Test
    void handleFor_producesExpectedResourceName() throws Exception {
        assertThat(driverWithFakeProject().handleFor("cred-1"))
                .isEqualTo("projects/example-project/secrets/certping-cred-1/versions/latest");
    }

    @Test
    void handleFor_rejectsInvalidName() throws Exception {
        assertThatThrownBy(() -> driverWithFakeProject().handleFor("has spaces"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void isOwnedByThisCertManager_trueForOwnHandle() throws Exception {
        assertThat(driverWithFakeProject().isOwnedByThisCertManager(
                "projects/example-project/secrets/certping-x/versions/1"))
                .isTrue();
    }

    @Test
    void isOwnedByThisCertManager_falseForForeignProject() throws Exception {
        assertThat(driverWithFakeProject().isOwnedByThisCertManager(
                "projects/other-project/secrets/certping-x/versions/latest"))
                .isFalse();
    }

    @Test
    void isOwnedByThisCertManager_falseForDifferentPrefix() throws Exception {
        assertThat(driverWithFakeProject().isOwnedByThisCertManager(
                "projects/example-project/secrets/foreign-x/versions/1"))
                .isFalse();
    }

    @Test
    void isOwnedByThisCertManager_acceptsParentFormWithoutVersion() throws Exception {
        assertThat(driverWithFakeProject().isOwnedByThisCertManager(
                "projects/example-project/secrets/certping-x"))
                .isTrue();
    }

    @Test
    void isOwnedByThisCertManager_falseForNullOrMalformed() throws Exception {
        assertThat(driverWithFakeProject().isOwnedByThisCertManager(null)).isFalse();
        assertThat(driverWithFakeProject().isOwnedByThisCertManager("not-a-resource-name")).isFalse();
    }

    @Test
    void deleteIfOwned_noopForBlankOrForeign() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithFakeProject();
        d.deleteIfOwned(null);
        d.deleteIfOwned("");
        d.deleteIfOwned("projects/other/secrets/certping-x/versions/1");
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    @Test
    void isAgentCertificateHandle_acceptsOnlyTheCertsOwnSecret() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithFakeProject();

        assertThat(d.isAgentCertificateHandle(
                "projects/example-project/secrets/certping-cert-123/versions/latest", "cert-123")).isTrue();
        assertThat(d.isAgentCertificateHandle(
                "projects/example-project/secrets/certping-certping-org7-cred-1/versions/3", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "projects/other-project/secrets/certping-cert-123/versions/latest", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(null, "cert-123")).isFalse();
    }

    // ── Project number: the API (and so the agent) names versions by project NUMBER ────────────

    private static final String PROJECT_NUMBER = "123456789012";
    /** The exact shape the agent persists: AddSecretVersion's version.getName(). */
    private static final String AGENT_PERSISTED_HANDLE =
            "projects/" + PROJECT_NUMBER + "/secrets/certping-cert-123/versions/3";

    private GcpSecretManagerAgentDriver driverWithProjectNumber(String projectNumber) throws Exception {
        GcpSecretManagerAgentDriver d = driverWithFakeProject();
        setField(d, "projectNumber", projectNumber);
        return d;
    }

    @Test
    void isAgentCertificateHandle_acceptsVersionedHandlesByProjectIdOrConfiguredNumber() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithProjectNumber(PROJECT_NUMBER);

        assertThat(d.isAgentCertificateHandle(AGENT_PERSISTED_HANDLE, "cert-123")).isTrue();
        assertThat(d.isAgentCertificateHandle(
                "projects/example-project/secrets/certping-cert-123/versions/7", "cert-123")).isTrue();
    }

    @Test
    void isAgentCertificateHandle_numberFormIsForeignUntilTheNumberIsConfigured() throws Exception {
        assertThat(driverWithFakeProject().isAgentCertificateHandle(AGENT_PERSISTED_HANDLE, "cert-123")).isFalse();
    }

    @Test
    void isAgentCertificateHandle_aConfiguredNumberLetsNoOtherProjectThrough() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithProjectNumber(PROJECT_NUMBER);

        assertThat(d.isAgentCertificateHandle(
                "projects/999999999999/secrets/certping-cert-123/versions/3", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "projects/1234567890123/secrets/certping-cert-123/versions/3", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "projects/other-project/secrets/certping-cert-123/versions/3", "cert-123")).isFalse();
    }

    @Test
    void isAgentCertificateHandle_rejectsAnotherSecretNameInEitherForm() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithProjectNumber(PROJECT_NUMBER);

        assertThat(d.isAgentCertificateHandle(
                "projects/" + PROJECT_NUMBER + "/secrets/certping-org7-cred-1/versions/3", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "projects/" + PROJECT_NUMBER + "/secrets/certping-cert-1234/versions/3", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "projects/example-project/secrets/cert-123/versions/3", "cert-123")).isFalse();
    }

    @Test
    void isAgentCertificateHandle_rejectsUnversionedHandles() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithProjectNumber(PROJECT_NUMBER);

        assertThat(d.isAgentCertificateHandle(
                "projects/" + PROJECT_NUMBER + "/secrets/certping-cert-123", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "projects/example-project/secrets/certping-cert-123", "cert-123")).isFalse();
    }

    @Test
    void ownershipAndDelete_recogniseTheNumberFormOnlyWhenConfigured() throws Exception {
        GcpSecretManagerAgentDriver configured = driverWithProjectNumber(PROJECT_NUMBER);
        SecretManagerServiceStub stub = mock(SecretManagerServiceStub.class);
        ScriptedCallable<DeleteSecretRequest, Empty> deletes = new ScriptedCallable<>(Empty.getDefaultInstance());
        when(stub.deleteSecretCallable()).thenReturn(deletes);
        setField(configured, "client", SecretManagerServiceClient.create(stub));

        assertThat(configured.isOwnedByThisCertManager(AGENT_PERSISTED_HANDLE)).isTrue();
        configured.deleteIfOwned(AGENT_PERSISTED_HANDLE);
        configured.deleteIfOwned("projects/999999999999/secrets/certping-cert-123/versions/3");
        assertThat(deletes.requests).extracting(DeleteSecretRequest::getName)
                .containsExactly("projects/" + PROJECT_NUMBER + "/secrets/certping-cert-123");

        GcpSecretManagerAgentDriver unconfigured = driverWithFakeProject();
        SecretManagerServiceStub otherStub = mock(SecretManagerServiceStub.class);
        setField(unconfigured, "client", SecretManagerServiceClient.create(otherStub));
        assertThat(unconfigured.isOwnedByThisCertManager(AGENT_PERSISTED_HANDLE)).isFalse();
        unconfigured.deleteIfOwned(AGENT_PERSISTED_HANDLE);
        verify(otherStub, never()).deleteSecretCallable();
    }

    @Test
    void read_destroyedOrDisabledVersion_isGone_butPermissionDeniedIsNot() throws Exception {
        GcpSecretManagerAgentDriver d = driverWithProjectNumber(PROJECT_NUMBER);
        SecretManagerServiceStub stub = mock(SecretManagerServiceStub.class);
        when(stub.accessSecretVersionCallable()).thenReturn(new ScriptedCallable<AccessSecretVersionRequest,
                AccessSecretVersionResponse>(apiException(StatusCode.Code.FAILED_PRECONDITION),
                apiException(StatusCode.Code.PERMISSION_DENIED), apiException(StatusCode.Code.RESOURCE_EXHAUSTED)));
        setField(d, "client", SecretManagerServiceClient.create(stub));

        assertThatThrownBy(() -> d.read(AGENT_PERSISTED_HANDLE)).isInstanceOf(AgentSecretGoneException.class);
        assertThatThrownBy(() -> d.read(AGENT_PERSISTED_HANDLE)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> d.read(AGENT_PERSISTED_HANDLE)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void init_rejectsANonNumericProjectNumber() {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getGcpSecretManager().setProjectId("example-project");
        props.getGcpSecretManager().setProjectNumber("example-project");
        GcpSecretManagerAgentDriver d = new GcpSecretManagerAgentDriver(
                props, new org.springframework.mock.env.MockEnvironment());

        assertThatThrownBy(d::init).isInstanceOf(IllegalStateException.class).hasMessageContaining("project-number");
    }

    private static ApiException apiException(StatusCode.Code code) {
        return ApiExceptionFactory.createException(new RuntimeException(code.name()), new FakeStatusCode(code), false);
    }

    /**
     * Answers each call with the next scripted outcome (an {@link ApiException} to fail with, or a
     * response), repeating the last one. SecretManagerServiceClient's methods are final, so tests
     * drive it through its stub instead of mocking it.
     */
    private static final class ScriptedCallable<Q, R> extends UnaryCallable<Q, R> {
        private final List<Object> outcomes;
        private final List<Q> requests = new ArrayList<>();

        ScriptedCallable(Object... outcomes) {
            this.outcomes = List.of(outcomes);
        }

        @Override
        @SuppressWarnings("unchecked")
        public ApiFuture<R> futureCall(Q request, ApiCallContext context) {
            requests.add(request);
            Object outcome = outcomes.get(Math.min(requests.size(), outcomes.size()) - 1);
            return outcome instanceof ApiException failure
                    ? ApiFutures.immediateFailedFuture(failure)
                    : ApiFutures.immediateFuture((R) outcome);
        }
    }

    private record FakeStatusCode(StatusCode.Code code) implements StatusCode {
        @Override
        public Code getCode() {
            return code;
        }

        @Override
        public Object getTransportCode() {
            return code.getHttpStatusCode();
        }
    }
}

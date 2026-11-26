// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.scep.ChallengeValidationException;
import com.certping.agent.scep.IntuneUnavailableException;
import com.certping.agent.scep.ResolvedEndpoint;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MicrosoftIntuneScepValidatorTest {

    private final IntuneScepClient client = mock(IntuneScepClient.class);
    private final DeviceSourceCredentialRegistry credentialRegistry =
            mock(DeviceSourceCredentialRegistry.class);
    private final MicrosoftIntuneScepValidator validator = new MicrosoftIntuneScepValidator(
            client, credentialRegistry, JsonMapper.builderWithJackson2Defaults().build(), "CertPing/1.0");

    private static ResolvedEndpoint endpoint(String profileRef) {
        return new ResolvedEndpoint(profileRef, "42", profileRef,
                DevicePlatformType.INTUNE, List.of("POSTPKIOperation"), null);
    }

    private void stubCredentials(String profileRef, String tenant) {
        stubCredentials(profileRef, tenant, "clientId");
    }

    private void stubCredentials(String profileRef, String tenant, String clientId) {
        when(credentialRegistry.requireCredentialsJson(profileRef, DevicePlatformType.INTUNE))
                .thenReturn("{\"tenantId\":\"" + tenant
                        + "\",\"clientId\":\"" + clientId
                        + "\",\"clientSecret\":\"secret\"}");
    }

    @Test
    void validateDiscoversThenValidatesOnFirstCall() {
        stubCredentials("intune-primary", "tenant");
        when(client.acquireToken("tenant", "clientId", "secret", IntuneScepClient.GRAPH_SCOPE))
                .thenReturn("graph-token");
        when(client.discoverValidationServiceUrl("graph-token")).thenReturn("https://scep.intune");
        when(client.acquireToken("tenant", "clientId", "secret", IntuneScepClient.MANAGE_SCOPE))
                .thenReturn("manage-token");

        ScepValidationResult result = validator.validate(endpoint("intune-primary"), "txn", "csr");

        verify(client).discoverValidationServiceUrl("graph-token");
        verify(client).validateRequest("https://scep.intune", "manage-token", "txn", "csr", "CertPing/1.0");
        // ValidateRequest proves the challenge, never an individual identifier field.
        assertThat(result.hasIdentifier()).isFalse();
    }

    @Test
    void validateSkipsDiscoveryOnceServiceUrlIsCachedForTheSource() {
        stubCredentials("intune-primary", "tenant");
        when(client.acquireToken("tenant", "clientId", "secret", IntuneScepClient.GRAPH_SCOPE))
                .thenReturn("graph-token");
        when(client.discoverValidationServiceUrl("graph-token")).thenReturn("https://scep.intune");
        when(client.acquireToken("tenant", "clientId", "secret", IntuneScepClient.MANAGE_SCOPE))
                .thenReturn("manage-token");

        validator.validate(endpoint("intune-primary"), "txn-1", "csr");
        validator.validate(endpoint("intune-primary"), "txn-2", "csr");

        verify(client, times(1)).discoverValidationServiceUrl(any());
        verify(client, times(2)).validateRequest(
                eq("https://scep.intune"), eq("manage-token"), any(), eq("csr"), eq("CertPing/1.0"));
    }

    @Test
    void eachSourceRouteValidatesAgainstItsOwnTenant() {
        stubCredentials("intune-primary", "tenant-a");
        stubCredentials("intune-secondary", "tenant-b");
        when(client.acquireToken(eq("tenant-a"), any(), any(), any())).thenReturn("token-a");
        when(client.acquireToken(eq("tenant-b"), any(), any(), any())).thenReturn("token-b");
        when(client.discoverValidationServiceUrl("token-a")).thenReturn("https://scep.tenant-a");
        when(client.discoverValidationServiceUrl("token-b")).thenReturn("https://scep.tenant-b");

        validator.validate(endpoint("intune-primary"), "txn-a", "csr");
        validator.validate(endpoint("intune-secondary"), "txn-b", "csr");

        verify(client).validateRequest("https://scep.tenant-a", "token-a", "txn-a", "csr", "CertPing/1.0");
        verify(client).validateRequest("https://scep.tenant-b", "token-b", "txn-b", "csr", "CertPing/1.0");
    }

    @Test
    void sourcesInSameTenantDoNotShareTokensAcrossClientIds() {
        stubCredentials("intune-primary", "shared-tenant", "client-a");
        stubCredentials("intune-secondary", "shared-tenant", "client-b");
        when(client.acquireToken(eq("shared-tenant"), eq("client-a"), any(), any()))
                .thenReturn("token-a");
        when(client.acquireToken(eq("shared-tenant"), eq("client-b"), any(), any()))
                .thenReturn("token-b");
        when(client.discoverValidationServiceUrl("token-a")).thenReturn("https://scep.tenant-a");
        when(client.discoverValidationServiceUrl("token-b")).thenReturn("https://scep.tenant-b");

        validator.validate(endpoint("intune-primary"), "txn-a", "csr");
        validator.validate(endpoint("intune-secondary"), "txn-b", "csr");

        verify(client).validateRequest(
                "https://scep.tenant-a", "token-a", "txn-a", "csr", "CertPing/1.0");
        verify(client).validateRequest(
                "https://scep.tenant-b", "token-b", "txn-b", "csr", "CertPing/1.0");
    }

    @Test
    void challengeRejectionPropagates() {
        stubCredentials("intune-primary", "tenant");
        when(client.acquireToken(any(), any(), any(), any())).thenReturn("token");
        when(client.discoverValidationServiceUrl(any())).thenReturn("https://scep.intune");
        doThrow(new ChallengeValidationException("rejected"))
                .when(client).validateRequest(any(), any(), any(), any(), any());

        assertThatThrownBy(() -> validator.validate(endpoint("intune-primary"), "txn", "csr"))
                .isInstanceOf(ChallengeValidationException.class);
    }

    @Test
    void outageDuringTokenPropagatesAsUnavailable() {
        stubCredentials("intune-primary", "tenant");
        when(client.acquireToken(any(), any(), any(), any()))
                .thenThrow(new IntuneUnavailableException("token endpoint down"));

        assertThatThrownBy(() -> validator.validate(endpoint("intune-primary"), "txn", "csr"))
                .isInstanceOf(IntuneUnavailableException.class);
        verify(client, never()).validateRequest(any(), any(), any(), any(), any());
    }

    @Test
    void malformedCredentialsFailWithoutLeakingContent() {
        when(credentialRegistry.requireCredentialsJson("intune-primary", DevicePlatformType.INTUNE))
                .thenReturn("{not-json");

        assertThatThrownBy(() -> validator.validate(endpoint("intune-primary"), "txn", "csr"))
                .isInstanceOf(IntuneUnavailableException.class)
                .hasMessageNotContaining("not-json");
        verify(client, never()).acquireToken(any(), any(), any(), any());
    }

    @Test
    void missingCredentialFieldIsRejected() {
        when(credentialRegistry.requireCredentialsJson("intune-primary", DevicePlatformType.INTUNE))
                .thenReturn("{\"tenantId\":\"tenant\",\"clientId\":\"clientId\"}");

        assertThatThrownBy(() -> validator.validate(endpoint("intune-primary"), "txn", "csr"))
                .isInstanceOf(IntuneUnavailableException.class)
                .hasMessageContaining("clientSecret");
    }

    @Test
    void notifySuccessAndFailureDelegate() {
        stubCredentials("intune-primary", "tenant");
        when(client.acquireToken(any(), any(), any(), any())).thenReturn("manage-token");
        when(client.discoverValidationServiceUrl(any())).thenReturn("https://scep.intune");

        assertThatCode(() -> {
            validator.notifySuccess(endpoint("intune-primary"), "txn", "csr", "thumb", "serial",
                    "2026-08-27T00:00:00.000Z", "issuer", "caConfig", "ca");
            validator.notifyFailure(endpoint("intune-primary"), "txn", "csr", 0x80070005L, "boom");
        }).doesNotThrowAnyException();

        verify(client).sendSuccessNotification("https://scep.intune", "manage-token", "txn", "csr",
                "thumb", "serial", "2026-08-27T00:00:00.000Z", "issuer", "caConfig", "ca", "CertPing/1.0");
        verify(client).sendFailureNotification(eq("https://scep.intune"), eq("manage-token"),
                eq("txn"), eq("csr"), anyLong(), eq("boom"), eq("CertPing/1.0"));
    }
}

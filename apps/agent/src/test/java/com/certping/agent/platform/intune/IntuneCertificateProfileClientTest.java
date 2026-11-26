// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

class IntuneCertificateProfileClientTest {
    private static final String COLLECTION =
            "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations";

    @Test
    void rejectsCollectionResponseWithoutAValueArray() {
        RestTemplate rest = mock(RestTemplate.class);
        when(rest.exchange(eq(COLLECTION), eq(HttpMethod.GET),
                any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("unexpected", true)));

        assertThatThrownBy(() -> new IntuneCertificateProfileClient(rest)
                .streamCertificateProfiles("token", ignored -> { }))
                .isInstanceOfSatisfying(PermanentAgentException.class, error -> {
                    assertThat(error.getErrorCode()).isEqualTo("PLATFORM_RESPONSE_INVALID");
                    assertThat(error).hasMessageContaining("value array");
                });
    }

    @Test
    void correlationRecoveryMatchesOnlyTheCanonicalFinalManagedMarker() {
        RestTemplate rest = mock(RestTemplate.class);
        Map<String, Object> spoofed = Map.of(
                "@odata.type", "#microsoft.graph.windows81SCEPCertificateProfile",
                "id", "spoofed",
                "description", "User text [certping:profile_1]");
        Map<String, Object> canonical = Map.of(
                "@odata.type", "#microsoft.graph.windows81SCEPCertificateProfile",
                "id", "owned",
                "description", """
                        User text [certping:spoof]
                        Managed by CertPing [certping:profile_1]""");
        when(rest.exchange(eq(COLLECTION), eq(HttpMethod.GET),
                any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("value", List.of(spoofed, canonical))));

        var match = new IntuneCertificateProfileClient(rest)
                .findByCorrelationMarker("token", "certping:profile_1");

        assertThat(match).contains(canonical);
    }

    @Test
    void streamsTheBoundedManagedCertificateStateReport() {
        RestTemplate rest = mock(RestTemplate.class);
        String url = COLLECTION + "/profile-1/microsoft.graph.macOSScepCertificateProfile"
                + "/managedDeviceCertificateStates"
                + "?$top=100";
        Map<String, Object> state = Map.of("certificateThumbprint", "ab".repeat(20));
        when(rest.exchange(eq(url), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("value", List.of(state))));

        List<Map<String, Object>> received = new java.util.ArrayList<>();
        new IntuneCertificateProfileClient(rest).streamManagedDeviceCertificateStates(
                "token", "profile-1", "#microsoft.graph.macOSScepCertificateProfile",
                received::addAll);

        assertThat(received).containsExactly(state);
        verify(rest).exchange(eq(url), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void assignReplacesTheProfileAssignmentsWithGroupTargets() {
        RestTemplate rest = mock(RestTemplate.class);
        String url = COLLECTION + "/profile-1/assign";
        when(rest.exchange(eq(url), eq(HttpMethod.POST), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of()));

        new IntuneCertificateProfileClient(rest).assign("token", "profile-1", List.of("g-1"));

        org.mockito.ArgumentCaptor<HttpEntity<Map<String, Object>>> request =
                org.mockito.ArgumentCaptor.forClass(HttpEntity.class);
        verify(rest).exchange(eq(url), eq(HttpMethod.POST), request.capture(), eq(Map.class));
        assertThat(request.getValue().getBody()).isEqualTo(Map.of("assignments", List.of(
                Map.of("target", Map.of(
                        "@odata.type", "#microsoft.graph.groupAssignmentTarget",
                        "groupId", "g-1")))));
    }

    @Test
    @SuppressWarnings("unchecked")
    void linksTheTrustedRootThroughTheScepProfileRootCertificateReference() {
        RestTemplate rest = mock(RestTemplate.class);
        String url = COLLECTION + "/scep-1/microsoft.graph.windows81SCEPCertificateProfile"
                + "/rootCertificate/$ref";
        when(rest.exchange(eq(url), eq(HttpMethod.PUT), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of()));

        new IntuneCertificateProfileClient(rest)
                .linkWindowsScepRootCertificate("token", "scep-1", "root-1");

        org.mockito.ArgumentCaptor<HttpEntity<Map<String, Object>>> request =
                org.mockito.ArgumentCaptor.forClass(HttpEntity.class);
        verify(rest).exchange(eq(url), eq(HttpMethod.PUT), request.capture(), eq(Map.class));
        assertThat(request.getValue().getBody())
                .containsEntry("@odata.id", COLLECTION + "('root-1')");
    }

    @Test
    void stopsManagedCertificateReportAtTheSuppliedPageBudget() {
        RestTemplate rest = mock(RestTemplate.class);
        String first = COLLECTION + "/profile-1/microsoft.graph.macOSScepCertificateProfile"
                + "/managedDeviceCertificateStates"
                + "?$top=100";
        String second = "https://graph.microsoft.com/beta/next-page";
        when(rest.exchange(eq(first), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of("value", List.of(), "@odata.nextLink", second)));

        assertThatThrownBy(() -> new IntuneCertificateProfileClient(rest)
                .streamManagedDeviceCertificateStates(
                        "token", "profile-1", "#microsoft.graph.macOSScepCertificateProfile",
                        1, ignored -> { }))
                .isInstanceOfSatisfying(PermanentAgentException.class, error ->
                        assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_CORRELATION_BUDGET_EXCEEDED"));
    }
}

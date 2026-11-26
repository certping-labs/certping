// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.ProfileObservedState;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.scep.AgentScepEndpointProvider;
import com.certping.agent.scep.ca.ScepCaBackend;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IntuneCertificateProfileConnectorTest {
    private static final DeviceSourceProfile SOURCE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Primary", null, Map.of());

    @Test
    void createRecoversNativeProfileByCorrelationMarkerBeforePosting() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        CertificateProfileMessage command = command("native-1");
        Map<String, Object> nativeProfile = Map.of("id", "native-1");
        ProfileObservedState observed = ProfileObservedState.builder()
                .providerProfileId("native-1")
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerCorrelationMarker("certping:profile_123")
                .build();
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        when(mapper.toWindowsScepPayload(command,
                List.of("https://scep.example.test/scep"))).thenReturn(Map.of("payload", true));
        when(client.findByCorrelationMarker("token", "certping:profile_123"))
                .thenReturn(Optional.of(nativeProfile));
        when(mapper.fromGraph(nativeProfile)).thenReturn(observed);

        ProfileObservedState result = new IntuneCertificateProfileConnector(
                sessions, client, mapper, scepEndpointProvider(), noScepCa()).create(SOURCE, command);

        assertThat(result).isSameAs(observed);
        verify(client, never()).create(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void createFailsBeforeAuthenticationWhenTheAgentScepListenerIsUnavailable() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileConnector connector = new IntuneCertificateProfileConnector(
                sessions,
                mock(IntuneCertificateProfileClient.class),
                mock(IntuneCertificateProfileMapper.class),
                new AgentScepEndpointProvider(new com.certping.agent.config.AgentProperties()),
                noScepCa());

        assertThatThrownBy(() -> connector.create(SOURCE, command("native-1")))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("SCEP_ENDPOINT_NOT_CONFIGURED"));
        verify(sessions, never()).open(any());
    }

    @Test
    void createRejectsCorrelationRecoveryWithAnIncompatibleNativeType() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        CertificateProfileMessage command = command("native-1");
        Map<String, Object> nativeProfile = Map.of("id", "native-1");
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        when(mapper.toWindowsScepPayload(eq(command), any())).thenReturn(Map.of("payload", true));
        when(client.findByCorrelationMarker("token", "certping:profile_123"))
                .thenReturn(Optional.of(nativeProfile));
        when(mapper.fromGraph(nativeProfile)).thenReturn(ProfileObservedState.builder()
                .providerProfileId("native-1")
                .providerProfileType("#microsoft.graph.iosScepCertificateProfile")
                .providerCorrelationMarker("certping:profile_123")
                .build());

        assertThatThrownBy(() -> new IntuneCertificateProfileConnector(
                sessions, client, mapper, scepEndpointProvider(), noScepCa()).create(SOURCE, command))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_OWNERSHIP_CONFLICT"));
        verify(client, never()).create(any(), any());
    }

    @Test
    void updateRejectsNativeProfileWithoutTheExpectedOwnershipMarker() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        CertificateProfileMessage command = command("native-1");
        Map<String, Object> nativeProfile = Map.of("id", "native-1");
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        when(mapper.toWindowsScepPayload(eq(command), any())).thenReturn(Map.of("payload", true));
        when(client.get("token", "native-1")).thenReturn(nativeProfile);
        when(mapper.fromGraph(nativeProfile)).thenReturn(ProfileObservedState.builder()
                .providerProfileId("native-1")
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerCorrelationMarker("certping:another-profile")
                .build());

        assertThatThrownBy(() -> new IntuneCertificateProfileConnector(
                sessions, client, mapper, scepEndpointProvider(), noScepCa()).update(SOURCE, command))
                .isInstanceOfSatisfying(PermanentAgentException.class,
                        error -> assertThat(error.getErrorCode())
                                .isEqualTo("PROFILE_OWNERSHIP_CONFLICT"));
        verify(client, never()).update(any(), any(), any());
    }

    @Test
    void streamsValidProfilesFromAPartiallyMalformedGraphPageBeforeFailingTheRun() {
        IntuneSessionProvider sessionProvider = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        DeviceSourceProfile source = new DeviceSourceProfile(
                "primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "Primary Intune", null, Map.of());
        Map<String, Object> validRaw = Map.of("id", "native-1");
        Map<String, Object> malformedRaw = Map.of("id", "native-2");
        ProfileObservedState valid = ProfileObservedState.builder()
                .providerProfileId("native-1").build();
        when(sessionProvider.open(source)).thenReturn(new IntuneSession("token"));
        when(mapper.fromGraphForDiscovery(validRaw)).thenReturn(valid);
        when(mapper.fromGraphForDiscovery(malformedRaw)).thenThrow(new PermanentAgentException(
                "PLATFORM_RESPONSE_INVALID", "Malformed native profile"));
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Consumer<List<Map<String, Object>>> consumer = invocation.getArgument(1);
            consumer.accept(List.of(validRaw, malformedRaw));
            return null;
        }).when(client).streamCertificateProfiles(eq("token"), any());
        List<ProfileObservedState> received = new ArrayList<>();
        IntuneCertificateProfileConnector connector =
                new IntuneCertificateProfileConnector(
                        sessionProvider, client, mapper, scepEndpointProvider(), noScepCa());

        assertThatThrownBy(() -> connector.streamProfiles(source, received::addAll))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("Malformed native profile");
        assertThat(received).containsExactly(valid);
    }

    @Test
    void createAddsTrustedRootFromTheCaChainRootLinksItAndAssignsBothProfiles() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        CertificateProfileMessage command = command(null);
        X509Certificate intermediate = mock(X509Certificate.class);
        X509Certificate root = mock(X509Certificate.class);
        Map<String, Object> scepPayload = Map.of("scep", true);
        Map<String, Object> rootPayload = Map.of("root", true);
        Map<String, Object> scepRaw = Map.of("id", "scep-1");
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        when(mapper.toWindowsScepPayload(command, List.of("https://scep.example.test/scep")))
                .thenReturn(scepPayload);
        when(mapper.assignmentGroupIds(command)).thenReturn(List.of(GROUP));
        when(mapper.toWindowsTrustedRootPayload(command, "certping:profile_123:root", root))
                .thenReturn(rootPayload);
        when(client.findByCorrelationMarker(eq("token"), any())).thenReturn(Optional.empty());
        when(client.create("token", scepPayload)).thenReturn(scepRaw);
        when(client.create("token", rootPayload)).thenReturn(Map.of("id", "root-1"));
        when(mapper.fromGraph(scepRaw)).thenReturn(observed("scep-1"));

        new IntuneCertificateProfileConnector(sessions, client, mapper, scepEndpointProvider(),
                scepCa(intermediate, root)).create(SOURCE, command);

        verify(client).linkWindowsScepRootCertificate("token", "scep-1", "root-1");
        verify(client).assign("token", "scep-1", List.of(GROUP));
        verify(client).assign("token", "root-1", List.of(GROUP));
    }

    @Test
    void updateLeavesAnUnchangedRootAloneAndKeepsAssignmentsWithoutGroupIds() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        CertificateProfileMessage command = command("scep-1");
        X509Certificate root = mock(X509Certificate.class);
        Map<String, Object> scepRaw = Map.of("id", "scep-1");
        Map<String, Object> rootRaw = Map.of("id", "root-1");
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        when(client.get("token", "scep-1")).thenReturn(scepRaw);
        when(client.update(eq("token"), eq("scep-1"), any())).thenReturn(scepRaw);
        when(mapper.fromGraph(scepRaw)).thenReturn(observed("scep-1"));
        when(client.findByCorrelationMarker("token", "certping:profile_123:root"))
                .thenReturn(Optional.of(rootRaw));
        when(client.get("token", "root-1")).thenReturn(rootRaw);
        when(mapper.holdsTrustedRoot(rootRaw, root)).thenReturn(true);
        when(mapper.assignmentGroupIds(command)).thenReturn(null);

        new IntuneCertificateProfileConnector(sessions, client, mapper, scepEndpointProvider(),
                scepCa(root)).update(SOURCE, command);

        verify(client, never()).update(eq("token"), eq("root-1"), any());
        verify(client).linkWindowsScepRootCertificate("token", "scep-1", "root-1");
        verify(client, never()).assign(any(), any(), any());
    }

    @Test
    void updateReplacesTheRootContentWhenTheCaRootChanged() {
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        IntuneCertificateProfileClient client = mock(IntuneCertificateProfileClient.class);
        IntuneCertificateProfileMapper mapper = mock(IntuneCertificateProfileMapper.class);
        CertificateProfileMessage command = command("scep-1");
        X509Certificate root = mock(X509Certificate.class);
        Map<String, Object> scepRaw = Map.of("id", "scep-1");
        Map<String, Object> rootRaw = Map.of("id", "root-1");
        Map<String, Object> rootPayload = Map.of("root", true);
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        when(client.get("token", "scep-1")).thenReturn(scepRaw);
        when(client.update(eq("token"), eq("scep-1"), any())).thenReturn(scepRaw);
        when(mapper.fromGraph(scepRaw)).thenReturn(observed("scep-1"));
        when(mapper.toWindowsTrustedRootPayload(command, "certping:profile_123:root", root))
                .thenReturn(rootPayload);
        when(client.findByCorrelationMarker("token", "certping:profile_123:root"))
                .thenReturn(Optional.of(rootRaw));
        when(client.get("token", "root-1")).thenReturn(rootRaw);

        new IntuneCertificateProfileConnector(sessions, client, mapper, scepEndpointProvider(),
                scepCa(root)).update(SOURCE, command);

        verify(client).update("token", "root-1", rootPayload);
    }

    private static final String GROUP = "8f6e0e4c-3c1a-4b8e-9d0f-2a1b3c4d5e6f";

    private static ProfileObservedState observed(String id) {
        return ProfileObservedState.builder()
                .providerProfileId(id)
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerCorrelationMarker("certping:profile_123")
                .build();
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<ScepCaBackend> noScepCa() {
        return mock(ObjectProvider.class);
    }

    private static ObjectProvider<ScepCaBackend> scepCa(X509Certificate... chain) {
        ScepCaBackend backend = mock(ScepCaBackend.class);
        when(backend.getCaChain()).thenReturn(List.of(chain));
        ObjectProvider<ScepCaBackend> provider = noScepCa();
        when(provider.getIfAvailable()).thenReturn(backend);
        return provider;
    }

    private static CertificateProfileMessage command(String nativeId) {
        return CertificateProfileMessage.builder()
                .providerProfileId(nativeId)
                .providerProfileType("#microsoft.graph.windows81SCEPCertificateProfile")
                .providerCorrelationMarker("certping:profile_123")
                .build();
    }

    private static AgentScepEndpointProvider scepEndpointProvider() {
        AgentScepEndpointProvider provider = mock(AgentScepEndpointProvider.class);
        when(provider.requireAdvertisedUrls(SOURCE)).thenReturn(
                List.of("https://scep.example.test/scep"));
        return provider;
    }
}

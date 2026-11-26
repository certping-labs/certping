// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.AgentScepEndpointProvider;
import com.certping.agent.scep.ResolvedEndpoint;
import com.certping.agent.scep.ScepProfileHintResolver.ScepProfileHint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IntuneScepProfileHintResolverTest {
    private static final String URL = "https://agent.example.test/scep/v1/intune-primary";
    private static final DeviceSourceProfile SOURCE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Primary", null, Map.of());
    private static final ResolvedEndpoint ENDPOINT = new ResolvedEndpoint(
            "intune-primary", "42", "intune-primary", DevicePlatformType.INTUNE, List.of(), null);

    private IntuneCertificateProfileClient client;
    private MutableClock clock;
    private IntuneScepProfileHintResolver resolver;

    @BeforeEach
    void setUp() {
        DeviceSourceProfileRegistry sources = mock(DeviceSourceProfileRegistry.class);
        when(sources.require("intune-primary", DevicePlatformType.INTUNE)).thenReturn(SOURCE);
        IntuneSessionProvider sessions = mock(IntuneSessionProvider.class);
        when(sessions.open(SOURCE)).thenReturn(new IntuneSession("token"));
        AgentScepEndpointProvider endpoints = mock(AgentScepEndpointProvider.class);
        when(endpoints.requireAdvertisedUrl("intune-primary")).thenReturn(URL);
        client = mock(IntuneCertificateProfileClient.class);
        clock = new MutableClock(Instant.parse("2026-11-18T00:00:00Z"));
        resolver = new IntuneScepProfileHintResolver(sources, sessions, client, endpoints, clock);
    }

    @Test
    void aSingleMatchingProfileGivesItsIdAndValidity() {
        graphReturns(scep("scep-1", URL + "/", 12, "months"),
                scep("other", "https://elsewhere.example.test/scep", 1, "years"),
                Map.of("@odata.type", "#microsoft.graph.windows81TrustedRootCertificate",
                        "id", "root-1"));

        assertThat(resolver.resolve(ENDPOINT))
                .isEqualTo(new ScepProfileHint("scep-1", Duration.ofHours(8760)));
    }

    @Test
    void severalProfilesShareTheValidityOnlyWhenTheyAgree() {
        graphReturns(scep("scep-1", URL, 1, "years"), scep("scep-2", URL, 365, "days"));
        assertThat(resolver.resolve(ENDPOINT))
                .isEqualTo(new ScepProfileHint(null, Duration.ofDays(365)));

        clock.advance(IntuneScepProfileHintResolver.CACHE_TTL);
        graphReturns(scep("scep-1", URL, 1, "years"), scep("scep-2", URL, 6, "months"));
        assertThat(resolver.resolve(ENDPOINT)).isEqualTo(ScepProfileHint.NONE);
    }

    @Test
    void cachesTheLookupAndFallsBackToCaDefaultsWhenGraphFails() {
        graphReturns(scep("scep-1", URL, 12, "months"));
        resolver.resolve(ENDPOINT);
        resolver.resolve(ENDPOINT);
        verify(client, times(1)).streamCertificateProfiles(eq("token"), any());

        clock.advance(IntuneScepProfileHintResolver.CACHE_TTL);
        doThrow(new TransientAgentException("PLATFORM_REQUEST_UNAVAILABLE", "offline"))
                .when(client).streamCertificateProfiles(eq("token"), any());
        assertThat(resolver.resolve(ENDPOINT)).isEqualTo(ScepProfileHint.NONE);
    }

    @SuppressWarnings("unchecked")
    private void graphReturns(Map<String, Object>... profiles) {
        doAnswer(invocation -> {
            ((Consumer<List<Map<String, Object>>>) invocation.getArgument(1))
                    .accept(List.of(profiles));
            return null;
        }).when(client).streamCertificateProfiles(eq("token"), any());
    }

    private static Map<String, Object> scep(String id, String url, int value, String scale) {
        return Map.of("@odata.type", "#microsoft.graph.windows81SCEPCertificateProfile",
                "id", id, "scepServerUrls", List.of(url),
                "certificateValidityPeriodValue", value,
                "certificateValidityPeriodScale", scale);
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}

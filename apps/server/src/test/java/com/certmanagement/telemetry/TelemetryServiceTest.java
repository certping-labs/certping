// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.telemetry;

import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserMfaRepository;
import com.certmanagement.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Properties;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.http.HttpMethod.POST;

class TelemetryServiceTest {

    private static final UUID INSTALLATION = UUID.fromString("2f0a5c1e-5a0e-4b9c-9f3b-0d7a3f1b2c4d");

    private final TelemetryProperties properties = new TelemetryProperties();
    private final InstallationIdentity installation = mock(InstallationIdentity.class);
    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final UserMfaRepository userMfa = mock(UserMfaRepository.class);
    private final CertificateRepository certificates = mock(CertificateRepository.class);
    private final DiscoveredCertRepository discovered = mock(DiscoveredCertRepository.class);
    private final DomainCredentialConfigRepository targets = mock(DomainCredentialConfigRepository.class);
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private MockRestServiceServer server;
    private TelemetryService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        properties.setEndpoint("https://telemetry.example.test/v1/report");
        when(installation.get()).thenReturn(INSTALLATION);
        when(organizations.count()).thenReturn(2L);
        when(users.count()).thenReturn(9L);
        when(userMfa.count()).thenReturn(3L);
        when(certificates.count()).thenReturn(140L);
        when(discovered.count()).thenReturn(1200L);
        when(targets.count()).thenReturn(7L);
        when(jdbc.execute(any(org.springframework.jdbc.core.ConnectionCallback.class))).thenReturn("PostgreSQL 16");
        Properties build = new Properties();
        build.setProperty("version", "0.1.0");
        ObjectProvider<BuildProperties> buildProvider = mock(ObjectProvider.class);
        when(buildProvider.getIfAvailable()).thenReturn(new BuildProperties(build));

        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        service = new TelemetryService(properties, installation, buildProvider, jdbc, organizations, users, userMfa,
                certificates, discovered, targets, Clock.fixed(Instant.parse("2026-10-26T10:00:00Z"), ZoneOffset.UTC),
                builder.build());
    }

    @Test
    void theReportCarriesOnlyTheDocumentedFields() {
        TelemetryReport report = service.preview();

        assertThat(report.schema()).isEqualTo("certping.telemetry.v1");
        assertThat(report.installationId()).isEqualTo(INSTALLATION.toString());
        assertThat(report.version()).isEqualTo("0.1.0");
        assertThat(report.edition()).isEqualTo("open");
        assertThat(report.runtime()).containsKeys("java", "os").containsEntry("database", "PostgreSQL 16");
        assertThat(report.counts()).containsExactly(
                java.util.Map.entry("organizations", 2L), java.util.Map.entry("users", 9L),
                java.util.Map.entry("usersWithMfa", 3L), java.util.Map.entry("certificates", 140L),
                java.util.Map.entry("discoveredCertificates", 1200L), java.util.Map.entry("deploymentTargets", 7L));
        assertThat(report.toString()).doesNotContain("@", "http", "example.com");
    }

    @Test
    void sendPostsJsonAndIsQuietWhenTheEndpointFails() {
        server.expect(requestTo("https://telemetry.example.test/v1/report")).andExpect(method(POST))
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.installationId").value(INSTALLATION.toString()))
                .andExpect(jsonPath("$.counts.certificates").value(140))
                .andRespond(withSuccess());
        assertThat(service.send()).isTrue();
        server.verify();

        server.reset();
        server.expect(requestTo("https://telemetry.example.test/v1/report")).andRespond(withServerError());
        assertThat(service.send()).isFalse();
    }

    @Test
    void theScheduleDoesNothingUnlessOptedIn() {
        properties.setEnabled(false);
        service.sendScheduled();
        server.verify(); // no request expected, none made

        properties.setEnabled(true);
        server.expect(requestTo("https://telemetry.example.test/v1/report")).andRespond(withSuccess());
        service.sendScheduled();
        server.verify();
    }

    @Test
    void aCountThatFailsBecomesMinusOneInsteadOfBreakingTheReport() {
        when(discovered.count()).thenThrow(new IllegalStateException("table missing"));
        assertThat(service.preview().counts()).containsEntry("discoveredCertificates", -1L);
    }
}

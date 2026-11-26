// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.handler.acme.AcmeAccountService;
import com.certping.agent.model.message.CaStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CaStatusReporterTest {

    private static final String ORG = "42";

    private AgentProperties properties;
    private AcmeAccountService accounts;
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-30T10:00:00Z"));
    private CaStatusReporter reporter;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.setOrganizationId(ORG);
        properties.getAcme().setDirectoryUrl(CaStatusReporter.LE_PRODUCTION);
        properties.getAcme().setAccountContact("ops+{organizationId}@example.com");
        accounts = mock(AcmeAccountService.class);
        Clock clock = new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        reporter = new CaStatusReporter(properties, accounts, clock);
    }

    @Test
    void reportsDirectoryEnvironmentContactAndAccount() {
        when(accounts.describeAccount(ORG)).thenReturn(Optional.of(new AcmeAccountService.AccountDescription(
                ORG, "https://acme.example/acct/1", "RSA 2048", Instant.parse("2026-10-01T00:00:00Z"))));

        CaStatus status = reporter.current();

        assertThat(status.getAcme().getDirectoryUrl()).isEqualTo(CaStatusReporter.LE_PRODUCTION);
        assertThat(status.getAcme().getEnvironment()).isEqualTo("PRODUCTION");
        assertThat(status.getAcme().getContactEmail()).isEqualTo("ops+42@example.com");
        assertThat(status.getAcme().getAccounts()).singleElement().satisfies(a -> {
            assertThat(a.getOrganizationId()).isEqualTo(ORG);
            assertThat(a.getAccountUrl()).isEqualTo("https://acme.example/acct/1");
            assertThat(a.getKeyType()).isEqualTo("RSA 2048");
            assertThat(a.getCreatedAt()).isEqualTo("2026-10-01T00:00:00Z");
        });
        assertThat(status.getGlobalsign().isConfigured()).isFalse();
    }

    @Test
    void environmentMapping() {
        assertThat(CaStatusReporter.environmentOf("https://acme-staging-v02.api.letsencrypt.org/directory/"))
                .isEqualTo("STAGING");
        assertThat(CaStatusReporter.environmentOf("HTTPS://acme-v02.api.letsencrypt.org:443/directory"))
                .isEqualTo("PRODUCTION");
        assertThat(CaStatusReporter.environmentOf("https://pebble:14000/dir")).isEqualTo("CUSTOM");
    }

    @Test
    void noAccountYet_emptyContact_andConfiguredCas_neverCarrySecrets() {
        properties.getAcme().setAccountContact("");
        properties.getGlobalsign().setApiBaseUrl("https://gs.example");
        properties.getGlobalsign().setApiKey("gs-key-value");
        properties.getGlobalsign().setApiSecret("gs-secret-value");
        properties.getGlobalsign().setClientPrivateKeyPemBase64("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t");
        when(accounts.describeAccount(ORG)).thenReturn(Optional.empty());

        CaStatus status = reporter.current();
        assertThat(status.getAcme().getContactEmail()).isEmpty();
        assertThat(status.getAcme().getAccounts()).isEmpty();
        assertThat(status.getGlobalsign().isConfigured()).isTrue();

        ObjectMapper json = JsonMapper.builder().build();
        String body = json.writeValueAsString(status);
        assertThat(body).doesNotContain("gs-key-value", "gs-secret-value", "LS0tLS1",
                "PRIVATE KEY", "BEGIN");
    }

    @Test
    void cachedUntilAccountChangesOrRefreshIsDue() {
        when(accounts.describeAccount(ORG)).thenReturn(Optional.empty());
        when(accounts.metadataVersion()).thenReturn(0L);

        assertThat(reporter.changedSinceLastReport()).isTrue();
        reporter.current();
        assertThat(reporter.changedSinceLastReport()).isFalse();
        reporter.current();
        verify(accounts, times(1)).describeAccount(ORG);

        when(accounts.metadataVersion()).thenReturn(1L);
        assertThat(reporter.changedSinceLastReport()).isTrue();
        reporter.current();
        verify(accounts, times(2)).describeAccount(ORG);

        now.set(now.get().plus(CaStatusReporter.REFRESH));
        reporter.current();
        verify(accounts, times(3)).describeAccount(ORG);
    }

    @Test
    void secretStoreFailure_keepsLastAccounts() {
        when(accounts.describeAccount(ORG)).thenReturn(Optional.of(new AcmeAccountService.AccountDescription(
                ORG, "https://acme.example/acct/1", "RSA 2048", null)));
        reporter.current();
        when(accounts.metadataVersion()).thenReturn(5L);
        when(accounts.describeAccount(ORG)).thenThrow(new IllegalStateException("store down"));

        CaStatus status = reporter.current();
        assertThat(status.getAcme().getAccounts()).singleElement()
                .satisfies(a -> assertThat(a.getAccountUrl()).isEqualTo("https://acme.example/acct/1"));
    }

    @Test
    void noDirectory_noAcmeSection() {
        properties.getAcme().setDirectoryUrl(" ");
        assertThat(reporter.current().getAcme()).isNull();
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.security.GatewayRequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentTokenControllerTest {

    @Mock private AgentTokenService tokens;

    @InjectMocks private AgentTokenController controller;

    private final AgentTokenService.AgentToken token = new AgentTokenService.AgentToken(
            5, 10, "edge", "cpa_abcdef", "a@b.com", OffsetDateTime.now(), null, null);

    @BeforeEach
    void orgAdmin() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void createsATokenWithTheCommandToStartAnAgent() {
        when(tokens.create(eq(10L), eq("edge"), any())).thenReturn(
                new AgentTokenService.CreatedToken(token, "cpa_abcdefSECRET"));

        var response = controller.create(null, new AgentTokenController.CreateRequest(" edge ",
                "https://certping.example.com"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        Map<String, Object> body = response.getBody();
        assertThat(body).containsEntry("value", "cpa_abcdefSECRET").containsEntry("token", token);
        assertThat((String) body.get("dockerCommand"))
                .contains("CERTPING_SERVER_URL=https://certping.example.com")
                .contains("CERTPING_AGENT_TOKEN=cpa_abcdefSECRET")
                .contains("SPRING_PROFILES_ACTIVE=selfhosted")
                // No version known in a unit test: the first release, never :latest.
                .endsWith("ghcr.io/certping-labs/certping-agent:0.0.1-beta")
                .doesNotContain(":latest");
    }

    @Test
    void startsTheAgentImageOfTheServersOwnRelease() {
        AgentTokenController released = new AgentTokenController(tokens, null, "v0.2.1");
        when(tokens.create(eq(10L), eq("agent"), any())).thenReturn(
                new AgentTokenService.CreatedToken(token, "cpa_x"));

        assertThat((String) released.create(null, null).getBody().get("dockerCommand"))
                .endsWith("ghcr.io/certping-labs/certping-agent:0.2.1");
    }

    @Test
    void picksTheReleaseVersionFromSettingThenBuildInfoThenTheFirstRelease() {
        java.util.Properties info = new java.util.Properties();
        info.setProperty("version", "0.3.0-rc.1");
        var build = new org.springframework.boot.info.BuildProperties(info);
        java.util.Properties snapshot = new java.util.Properties();
        snapshot.setProperty("version", "0.0.1-SNAPSHOT");
        var snapshotBuild = new org.springframework.boot.info.BuildProperties(snapshot);

        assertThat(AgentTokenController.agentVersion(" 0.4.0 ", build)).isEqualTo("0.4.0");
        assertThat(AgentTokenController.agentVersion("", build)).isEqualTo("0.3.0-rc.1");
        assertThat(AgentTokenController.agentVersion("dev", snapshotBuild)).isEqualTo("0.0.1-beta");
        assertThat(AgentTokenController.agentVersion("latest", null)).isEqualTo("0.0.1-beta");
        assertThat(AgentTokenController.agentVersion(null, null)).isEqualTo("0.0.1-beta");
    }

    @Test
    void defaultsTheNameAndUrlAndRejectsLongNames() {
        when(tokens.create(eq(10L), eq("agent"), any())).thenReturn(
                new AgentTokenService.CreatedToken(token, "cpa_x"));
        assertThat((String) controller.create(null, null).getBody().get("dockerCommand"))
                .contains("https://<your-certping-host>");

        assertThatThrownBy(() -> controller.create(null,
                new AgentTokenController.CreateRequest("x".repeat(101), null)))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void anExpiryInDaysMakesATokenThatExpires() {
        when(tokens.create(eq(10L), eq("edge"), any(), any(OffsetDateTime.class))).thenReturn(
                new AgentTokenService.CreatedToken(token, "cpa_x"));
        OffsetDateTime before = OffsetDateTime.now();

        controller.create(null, new AgentTokenController.CreateRequest("edge", null, 90));

        org.mockito.ArgumentCaptor<OffsetDateTime> expiry = org.mockito.ArgumentCaptor.forClass(OffsetDateTime.class);
        org.mockito.Mockito.verify(tokens).create(eq(10L), eq("edge"), any(), expiry.capture());
        assertThat(expiry.getValue()).isBetween(before.plusDays(90).minusMinutes(1), before.plusDays(90).plusMinutes(1));
    }

    @Test
    void withoutAnExpiryTheTokenNeverExpiresAndABadExpiryIsRefused() {
        when(tokens.create(eq(10L), eq("edge"), any())).thenReturn(new AgentTokenService.CreatedToken(token, "cpa_x"));
        controller.create(null, new AgentTokenController.CreateRequest("edge", null, null));
        org.mockito.Mockito.verify(tokens).create(eq(10L), eq("edge"), any());

        for (int days : new int[] {0, -1, AgentTokenController.MAX_EXPIRES_IN_DAYS + 1}) {
            assertThatThrownBy(() -> controller.create(null, new AgentTokenController.CreateRequest("edge", null, days)))
                    .isInstanceOfSatisfying(ResponseStatusException.class,
                            e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST));
        }
    }

    @Test
    void listsAndRevokesWithinTheCallersOrganization() {
        when(tokens.list(10L)).thenReturn(List.of(token));
        assertThat(controller.list(null)).containsExactly(token);

        when(tokens.revoke(10L, 5L)).thenReturn(true);
        assertThat(controller.revoke(5L, null).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        when(tokens.revoke(10L, 6L)).thenReturn(false);
        assertThatThrownBy(() -> controller.revoke(6L, null)).isInstanceOf(ResponseStatusException.class);
    }
}

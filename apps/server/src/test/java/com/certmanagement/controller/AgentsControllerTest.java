// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.agent.AgentDeepHealthTriggerResponseDto;
import com.certmanagement.dto.agent.AgentView;
import com.certmanagement.enums.AgentDeepHealthCheckStatus;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentDirectoryService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.server.ResponseStatusException;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentsControllerTest {

    @Mock private AgentDirectoryService directory;
    @Mock private AgentDeepHealthCheckService deepHealthChecks;

    @InjectMocks private AgentsController controller;

    @BeforeEach
    void orgAdmin() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private static AgentView agent(String id, boolean revoked) {
        return new AgentView(id, "edge", "cpa_abcdef", "2026-10-01T00:00Z", null, revoked,
                revoked ? "OFFLINE" : "ONLINE", "2026-10-31T11:59Z", "0.2.0", "edge-1", "Linux aarch64", "25.0.1",
                "LOCAL", 8, false, true, null, null,
                new AgentView.Capabilities(List.of("AZURE_KEYVAULT"), List.of(), List.of("CLOUDFLARE")));
    }

    @Test
    void listsTheCallersOrganization() {
        when(directory.list(10L)).thenReturn(List.of(agent("5", false)));

        AgentView.AgentList body = controller.list(null);

        assertThat(body.agents()).extracting(AgentView::agentId).containsExactly("5");
        verify(directory).list(10L);
    }

    @Test
    void anOrgAdminCannotListAnotherOrganization() {
        assertThatThrownBy(() -> controller.list(11L)).isInstanceOf(AccessDeniedException.class);
        verify(directory, never()).list(anyLong());
    }

    @Test
    void getsOneAgentOfTheOrganization() {
        when(directory.get(10L, 5L)).thenReturn(Optional.of(agent("5", false)));
        assertThat(controller.get("5", null).agentId()).isEqualTo("5");
    }

    @Test
    void anotherOrganizationsAgentIsNotFound() {
        when(directory.get(10L, 77L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> controller.get("77", null))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
        assertThatThrownBy(() -> controller.get("not-a-number", null))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
    }

    @Test
    void healthCheckRunsTheOrganizationsDeepCheck() {
        when(directory.get(10L, 5L)).thenReturn(Optional.of(agent("5", false)));
        OffsetDateTime at = OffsetDateTime.parse("2026-10-31T12:00:00Z");
        when(deepHealthChecks.trigger(10L)).thenReturn(AgentDeepHealthTriggerResponseDto.builder()
                .deepCheckId("dhc-1").status(AgentDeepHealthCheckStatus.PENDING).requestedAt(at).build());

        var response = controller.healthCheck("5", null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).containsEntry("agentId", "5").containsEntry("scope", "ORGANIZATION")
                .containsEntry("deepCheckId", "dhc-1").containsEntry("status", "PENDING")
                .containsEntry("requestedAt", at.toString());
    }

    @Test
    void healthCheckRefusesAnotherOrganizationsAgentAndRevokedTokens() {
        when(directory.get(10L, 77L)).thenReturn(Optional.empty());
        when(directory.get(10L, 6L)).thenReturn(Optional.of(agent("6", true)));

        assertThatThrownBy(() -> controller.healthCheck("77", null))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
        assertThatThrownBy(() -> controller.healthCheck("6", null))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.CONFLICT));
        verify(deepHealthChecks, never()).trigger(anyLong());
    }

    @Test
    void needsTheSameRolesAsTheAgentTokenList() {
        assertThat(AgentsController.class.getAnnotation(PreAuthorize.class).value())
                .isEqualTo(AgentTokenController.class.getAnnotation(PreAuthorize.class).value());
    }
}

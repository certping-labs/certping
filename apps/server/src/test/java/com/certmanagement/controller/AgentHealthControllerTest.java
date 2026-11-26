// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.agent.AgentHealthResponseDto;
import com.certmanagement.dto.agent.AgentHeartbeatCadenceDto;
import com.certmanagement.dto.agent.UpdateAgentHeartbeatCadenceRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.agent.AgentHealthService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentHealthControllerTest {

    @Mock private AgentHealthService agentHealthService;

    @InjectMocks private AgentHealthController controller;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void getAgentHealth_returnsOk() {
        AgentHealthResponseDto dto = AgentHealthResponseDto.builder().build();
        when(agentHealthService.getOrganizationHealthView(10L)).thenReturn(dto);

        ResponseEntity<AgentHealthResponseDto> response = controller.getAgentHealth();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(dto);
    }

    @Test
    void getHeartbeatCadence_returnsMinutes() {
        when(agentHealthService.getHeartbeatCadenceMinutes(10L)).thenReturn(15);

        ResponseEntity<AgentHeartbeatCadenceDto> response = controller.getHeartbeatCadence();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getHeartbeatCadenceMinutes()).isEqualTo(15);
    }

    @Test
    void updateHeartbeatCadence_returnsUpdatedMinutes() {
        UpdateAgentHeartbeatCadenceRequest req = new UpdateAgentHeartbeatCadenceRequest();
        req.setHeartbeatCadenceMinutes(30);
        when(agentHealthService.updateHeartbeatCadenceMinutes(10L, 30)).thenReturn(30);

        ResponseEntity<AgentHeartbeatCadenceDto> response = controller.updateHeartbeatCadence(req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getHeartbeatCadenceMinutes()).isEqualTo(30);
        verify(agentHealthService).updateHeartbeatCadenceMinutes(10L, 30);
    }
}

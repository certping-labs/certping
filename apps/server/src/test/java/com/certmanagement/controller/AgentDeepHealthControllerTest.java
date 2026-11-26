// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.agent.AgentDeepHealthCheckDto;
import com.certmanagement.dto.agent.AgentDeepHealthMetricDto;
import com.certmanagement.dto.agent.AgentDeepHealthTriggerResponseDto;
import com.certmanagement.dto.agent.TriggerAgentDeepHealthRequest;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentDeepHealthControllerTest {

    @Mock private AgentDeepHealthCheckService deepHealthCheckService;

    @InjectMocks private AgentDeepHealthController controller;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void trigger_orgFromJwt_returnsOk() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
        AgentDeepHealthTriggerResponseDto dto = AgentDeepHealthTriggerResponseDto.builder().build();
        when(deepHealthCheckService.trigger(10L)).thenReturn(dto);

        ResponseEntity<AgentDeepHealthTriggerResponseDto> response = controller.trigger(null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(dto);
    }

    @Test
    void trigger_nonSuperAdminWithBodyOrg_throwsAccessDenied() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
        TriggerAgentDeepHealthRequest req = new TriggerAgentDeepHealthRequest();
        req.setOrganizationId(99L);

        assertThatThrownBy(() -> controller.trigger(req))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void trigger_noJwtOrg_throwsBadRequest() {
        GatewayRequestContext.set(1, null, "req", "a@b.com");

        assertThatThrownBy(() -> controller.trigger(null))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void list_returnsPage() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
        Page<AgentDeepHealthCheckDto> page = new PageImpl<>(List.of());
        when(deepHealthCheckService.list(eq(10L), any(Pageable.class))).thenReturn(page);

        ResponseEntity<Page<AgentDeepHealthCheckDto>> response = controller.list(null, 0, 20);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(page);
    }

    @Test
    void list_nonSuperWithQueryOrg_throwsAccessDenied() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");

        assertThatThrownBy(() -> controller.list(99L, 0, 20))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void get_returnsOk() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
        AgentDeepHealthCheckDto dto = AgentDeepHealthCheckDto.builder().build();
        when(deepHealthCheckService.get(10L, "chk-1")).thenReturn(dto);

        ResponseEntity<AgentDeepHealthCheckDto> response = controller.get("chk-1", null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(dto);
    }

    @Test
    void get_notFoundOnIllegalArgument() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
        when(deepHealthCheckService.get(10L, "missing")).thenThrow(new IllegalArgumentException("nope"));

        ResponseEntity<AgentDeepHealthCheckDto> response = controller.get("missing", null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void metrics_returnsOk() {
        GatewayRequestContext.set(1, "10", "req", "a@b.com");
        List<AgentDeepHealthMetricDto> metrics = List.of(AgentDeepHealthMetricDto.builder().build());
        when(deepHealthCheckService.getMetrics(10L, "chk-1")).thenReturn(metrics);

        ResponseEntity<List<AgentDeepHealthMetricDto>> response = controller.metrics("chk-1", null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(metrics);
    }

    @Test
    void get_superAdminWithoutQueryOrg_readsTheOrganizationTheyWorkIn() {
        GatewayRequestContext.set(1, "10", "req", "admin@b.com");
        org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("admin", null,
                        List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));
        try {
            AgentDeepHealthCheckDto dto = AgentDeepHealthCheckDto.builder().build();
            when(deepHealthCheckService.get(10L, "chk-1")).thenReturn(dto);

            assertThat(controller.get("chk-1", null).getBody()).isSameAs(dto);
        } finally {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
    }
}

// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.agent.AgentHealthResponseDto;
import com.certmanagement.dto.agent.AgentHeartbeatCadenceDto;
import com.certmanagement.dto.agent.UpdateAgentHeartbeatCadenceRequest;
import com.certmanagement.service.agent.AgentHealthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.CERTIFICATE_READ;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;

@RestController
@RequiredArgsConstructor
@Tag(name = "Agent Health", description = "APIs for organization-scoped cert-agent health status")
@SecurityRequirement(name = "bearerAuth")
public class AgentHealthController {

    private final AgentHealthService agentHealthService;

    @GetMapping(Paths.AGENT_HEALTH)
    @FeatureGated(FeatureFlags.AGENT_HEALTH_MONITORING)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get latest agent health snapshot for the authenticated organization")
    public ResponseEntity<AgentHealthResponseDto> getAgentHealth() {
        Long resolvedOrgId = OrgResolver.fromJwt();
        AgentHealthResponseDto response = agentHealthService.getOrganizationHealthView(resolvedOrgId);
        return ResponseEntity.ok(response);
    }

    @GetMapping(Paths.AGENT_HEALTH_CADENCE)
    @FeatureGated(FeatureFlags.AGENT_HEALTH_MONITORING)
    @PreAuthorize("hasRole('" + ROLE_ORGANIZATION_ADMIN + "') or hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Get heartbeat cadence (minutes) for the authenticated organization")
    public ResponseEntity<AgentHeartbeatCadenceDto> getHeartbeatCadence() {
        Long resolvedOrgId = OrgResolver.fromJwt();
        int minutes = agentHealthService.getHeartbeatCadenceMinutes(resolvedOrgId);
        return ResponseEntity.ok(AgentHeartbeatCadenceDto.builder().heartbeatCadenceMinutes(minutes).build());
    }

    @PutMapping(Paths.AGENT_HEALTH_CADENCE)
    @FeatureGated(FeatureFlags.AGENT_HEALTH_MONITORING)
    @PreAuthorize("hasRole('" + ROLE_ORGANIZATION_ADMIN + "') or hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Update heartbeat cadence (minutes) for the authenticated organization")
    @AuditFailure(AuditEventType.AGENT_HEALTH_CADENCE_CHANGED)
    public ResponseEntity<AgentHeartbeatCadenceDto> updateHeartbeatCadence(
            @Valid @RequestBody UpdateAgentHeartbeatCadenceRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();
        int minutes = agentHealthService.updateHeartbeatCadenceMinutes(
                resolvedOrgId,
                request.getHeartbeatCadenceMinutes());
        return ResponseEntity.ok(AgentHeartbeatCadenceDto.builder().heartbeatCadenceMinutes(minutes).build());
    }
}

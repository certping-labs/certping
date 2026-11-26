// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.agent.AgentDeepHealthCheckDto;
import com.certmanagement.dto.agent.AgentDeepHealthMetricDto;
import com.certmanagement.dto.agent.AgentDeepHealthTriggerResponseDto;
import com.certmanagement.dto.agent.TriggerAgentDeepHealthRequest;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.certmanagement.security.Permissions.AGENT_DEEP_HEALTH_READ;
import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

@RestController
@RequiredArgsConstructor
@Tag(name = "Agent Deep Health", description = "APIs for organization-scoped deep health checks")
@SecurityRequirement(name = "bearerAuth")
public class AgentDeepHealthController {

    private final AgentDeepHealthCheckService deepHealthCheckService;

    @PostMapping(Paths.AGENT_DEEP_HEALTH_CHECKS)
    @PreAuthorize("hasRole('" + ROLE_ORGANIZATION_ADMIN + "') or hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Trigger a new deep health check for the authenticated organization")
    @AuditFailure(value = AuditEventType.AGENT_HEALTH_DEEP_CHECK_REQUESTED, organization = "#request?.organizationId")
    public ResponseEntity<AgentDeepHealthTriggerResponseDto> trigger(
            @RequestBody(required = false) TriggerAgentDeepHealthRequest request) {
        Long organizationId = resolveOrganizationIdForTrigger(request);
        return ResponseEntity.ok(deepHealthCheckService.trigger(organizationId));
    }

    @GetMapping(Paths.AGENT_DEEP_HEALTH_CHECKS)
    @PreAuthorize("hasPermission(null, '" + AGENT_DEEP_HEALTH_READ + "')")
    @Operation(summary = "List deep health checks for the authenticated organization")
    public ResponseEntity<Page<AgentDeepHealthCheckDto>> list(
            @RequestParam(required = false) Long organizationId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Long resolved = resolveOrganizationIdForRead(organizationId);
        PageRequest pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "requestedAt"));
        return ResponseEntity.ok(deepHealthCheckService.list(resolved, pageable));
    }

    @GetMapping(Paths.AGENT_DEEP_HEALTH_CHECK)
    @PreAuthorize("hasPermission(null, '" + AGENT_DEEP_HEALTH_READ + "')")
    @Operation(summary = "Get a deep health check by id for the authenticated organization")
    public ResponseEntity<AgentDeepHealthCheckDto> get(
            @PathVariable String deepCheckId,
            @RequestParam(required = false) Long organizationId) {
        Long resolved = resolveOrganizationIdForRead(organizationId);
        try {
            return ResponseEntity.ok(deepHealthCheckService.get(resolved, deepCheckId));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping(Paths.AGENT_DEEP_HEALTH_CHECK_METRICS)
    @PreAuthorize("hasPermission(null, '" + AGENT_DEEP_HEALTH_READ + "')")
    @Operation(summary = "Get deep health check metrics by id for the authenticated organization")
    public ResponseEntity<List<AgentDeepHealthMetricDto>> metrics(
            @PathVariable String deepCheckId,
            @RequestParam(required = false) Long organizationId) {
        Long resolved = resolveOrganizationIdForRead(organizationId);
        return ResponseEntity.ok(deepHealthCheckService.getMetrics(resolved, deepCheckId));
    }

    private Long resolveOrganizationIdForTrigger(TriggerAgentDeepHealthRequest request) {
        Long fromBody = request != null ? request.getOrganizationId() : null;
        if (OrgResolver.isSuperAdmin()) {
            if (fromBody == null) {
                throw new BadRequestException("organizationId is required in the request body for SUPER_ADMIN");
            }
            return fromBody;
        }
        if (fromBody != null) {
            throw new AccessDeniedException("Only SUPER_ADMIN may specify organizationId in the request body");
        }
        return requireOrganizationIdFromJwt("JWT organization context is required to trigger a deep health check");
    }

    private Long resolveOrganizationIdForRead(Long queryOrganizationId) {
        if (OrgResolver.isSuperAdmin()) {
            return OrgResolver.resolve(queryOrganizationId);
        }
        if (queryOrganizationId != null) {
            throw new AccessDeniedException("Only SUPER_ADMIN may specify the organizationId query parameter");
        }
        return requireOrganizationIdFromJwt("JWT organization context is required");
    }

    private Long requireOrganizationIdFromJwt(String messageWhenMissing) {
        String raw = GatewayRequestContext.getOrganizationId();
        if (raw == null || raw.isBlank()) {
            throw new BadRequestException(messageWhenMissing);
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException ex) {
            throw new BadRequestException("Invalid organizationId in JWT context");
        }
    }
}

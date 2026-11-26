// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.agent.AgentDeepHealthTriggerResponseDto;
import com.certmanagement.dto.agent.AgentView;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentDirectoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * The Agents page: each agent token of an organization with what its agent reports about itself.
 * Read only: agent settings stay on the agent. Same access as the agent token list: org admins see
 * their own organization, super admins pass {@code organizationId}.
 */
@RestController
@RequestMapping("/api/v1/agents")
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "') or hasRole('" + ROLE_ORGANIZATION_ADMIN + "')")
@Tag(name = "Agents", description = "The agents of an organization and what they report")
public class AgentsController {

    private final AgentDirectoryService directory;
    private final AgentDeepHealthCheckService deepHealthChecks;

    public AgentsController(AgentDirectoryService directory, AgentDeepHealthCheckService deepHealthChecks) {
        this.directory = directory;
        this.deepHealthChecks = deepHealthChecks;
    }

    @GetMapping
    @Operation(summary = "Lists the organization's agents, revoked and expired ones included, online first")
    public AgentView.AgentList list(@RequestParam(value = "organizationId", required = false) Long organizationId) {
        return new AgentView.AgentList(directory.list(OrgResolver.resolve(organizationId)));
    }

    @GetMapping("/{agentId}")
    @Operation(summary = "One agent of the organization")
    public AgentView get(@PathVariable String agentId,
                         @RequestParam(value = "organizationId", required = false) Long organizationId) {
        return find(OrgResolver.resolve(organizationId), agentId);
    }

    /**
     * Runs the organization's deep health check. Commands go to the organization's queue and any of
     * its agents may answer, so the check covers the organization, not this agent alone; the agent
     * must belong to the organization and still be able to connect.
     */
    @PostMapping("/{agentId}/health-check")
    @Operation(summary = "Triggers the organization's deep health check from an agent's page")
    public ResponseEntity<Map<String, Object>> healthCheck(
            @PathVariable String agentId,
            @RequestParam(value = "organizationId", required = false) Long organizationId) {
        Long orgId = OrgResolver.resolve(organizationId);
        AgentView agent = find(orgId, agentId);
        if (agent.revoked()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "agent token is revoked or expired");
        }
        AgentDeepHealthTriggerResponseDto triggered = deepHealthChecks.trigger(orgId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agentId", agent.agentId());
        body.put("scope", "ORGANIZATION");
        body.put("deepCheckId", triggered.getDeepCheckId());
        body.put("status", triggered.getStatus() == null ? null : triggered.getStatus().name());
        body.put("requestedAt", triggered.getRequestedAt() == null ? null : triggered.getRequestedAt().toString());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(body);
    }

    private AgentView find(long organizationId, String agentId) {
        long id;
        try {
            id = Long.parseLong(agentId);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "agent not found");
        }
        return directory.get(organizationId, id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "agent not found"));
    }
}
